"""fw-audit command-line interface."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer

from fw_audit import __version__
from fw_audit.classify.engine import ClassificationEngine, load_policy
from fw_audit.graph.flows import build_flows, summary_counts
from fw_audit.pipeline import run_audit, _discover_inputs
from fw_audit.policy.loader import load_hosts
from fw_audit.parsers.detector import parse_file

app = typer.Typer(
    name="fw-audit",
    help="Firewall ruleset and network exposure audit tool (home lab).",
    no_args_is_help=True,
)


def _xslt_path() -> Path:
    return Path(__file__).resolve().parent / "report" / "templates" / "audit-report.xsl"


@app.command("version")
def version_cmd() -> None:
    typer.echo(f"fw-audit {__version__}")


@app.command("ingest")
def ingest(
    path: Path = typer.Argument(..., help="File or directory of netstat/ss exports"),
    hosts: Optional[Path] = typer.Option(None, "--hosts", help="hosts.yaml inventory"),
) -> None:
    """Validate inputs and print summary."""
    for file_path, host_key in _discover_inputs(path):
        host = load_hosts(hosts).get(host_key)
        hid = host.id if host else "H001"
        listeners, parser = parse_file(file_path, hid)
        typer.echo(f"{file_path}: parser={parser} listeners={len(listeners)} host={host_key}")


@app.command("analyze")
def analyze(
    path: Path = typer.Argument(..., help="File or directory of exports"),
    hosts: Optional[Path] = typer.Option(None, "--hosts"),
    policy: Optional[Path] = typer.Option(None, "--policy"),
    format: str = typer.Option("text", "--format", help="text or json"),
) -> None:
    """Classify listeners and print findings."""
    hosts_map = load_hosts(hosts)
    pol = load_policy(policy)
    engine = ClassificationEngine(pol)
    all_listeners = []

    for file_path, host_key in _discover_inputs(path):
        host = hosts_map.get(host_key) or Host_fallback(hosts_map, host_key)
        listeners, _ = parse_file(file_path, host.id)
        all_listeners.extend(listeners)

    by_id = {h.id: h for h in hosts_map.values() if h.id.startswith("H")}
    findings = engine.apply_to_listeners(all_listeners, by_id)
    flows = build_flows(all_listeners, by_id)

    if format == "json":
        typer.echo(
            json.dumps(
                {
                    "summary": summary_counts(flows),
                    "findings": [
                        {
                            "code": f.code,
                            "severity": f.severity.value,
                            "message": f.message,
                        }
                        for f in findings
                    ],
                },
                indent=2,
            )
        )
    else:
        typer.echo("Classification summary:")
        for cat, count in summary_counts(flows).items():
            typer.echo(f"  {cat}: {count}")
        typer.echo(f"\nFindings ({len(findings)}):")
        for f in findings:
            typer.echo(f"  [{f.severity.value}] {f.code}: {f.message}")


def Host_fallback(hosts_map, host_key):
    from fw_audit.models import Host

    return Host(id="H001", hostname=host_key, zone="internal")


@app.command("report")
def report(
    path: Path = typer.Argument(..., help="Input path"),
    output_dir: Path = typer.Option(Path("out"), "--output-dir", "-o"),
    hosts: Optional[Path] = typer.Option(None, "--hosts"),
    policy: Optional[Path] = typer.Option(None, "--policy"),
    operator: str = typer.Option("home-lab", "--operator"),
) -> None:
    """Generate XML audit report only."""
    run_audit(
        path,
        output_dir,
        hosts_file=hosts,
        policy_file=policy,
        operator=operator,
        platforms=[],
    )
    typer.echo(f"Report: {output_dir / 'audit-report.xml'}")


@app.command("generate")
def generate(
    path: Path = typer.Argument(..., help="Input path"),
    output_dir: Path = typer.Option(Path("out"), "--output-dir", "-o"),
    hosts: Optional[Path] = typer.Option(None, "--hosts"),
    policy: Optional[Path] = typer.Option(None, "--policy"),
    platform: str = typer.Option(
        "all",
        "--platform",
        help="windows, nftables, or all",
    ),
) -> None:
    """Generate firewall rulesets."""
    platforms = []
    if platform in ("all", "windows"):
        platforms.append("windows")
    if platform in ("all", "nftables", "linux"):
        platforms.append("nftables")
    ctx = run_audit(
        path,
        output_dir,
        hosts_file=hosts,
        policy_file=policy,
        platforms=platforms,
    )
    for art in ctx.rulesets:
        typer.echo(f"Ruleset: {art.path} ({art.rule_count} rules)")


@app.command("html")
def html(
    xml: Path = typer.Argument(..., help="audit-report.xml path"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """Transform XML to HTML using XSLT (requires xsltproc)."""
    xsltproc = shutil.which("xsltproc")
    if not xsltproc:
        typer.echo("xsltproc not found; install libxslt.", err=True)
        raise typer.Exit(1)

    out = output or xml.with_suffix(".html")
    xsl = _xslt_path()
    subprocess.run(
        [xsltproc, "-o", str(out), str(xsl), str(xml)],
        check=True,
    )
    typer.echo(f"HTML: {out}")


@app.command("all-in-one")
def all_in_one(
    path: Path = typer.Argument(..., help="Input file or directory"),
    output_dir: Path = typer.Option(Path("out"), "--output-dir", "-o"),
    hosts: Optional[Path] = typer.Option(None, "--hosts"),
    policy: Optional[Path] = typer.Option(None, "--policy"),
    operator: str = typer.Option("home-lab", "--operator"),
    platform: str = typer.Option("all", "--platform"),
) -> None:
    """Generate rulesets, XML report, and HTML (if xsltproc available)."""
    platforms = []
    if platform in ("all", "windows"):
        platforms.append("windows")
    if platform in ("all", "nftables", "linux"):
        platforms.append("nftables")

    ctx = run_audit(
        path,
        output_dir,
        hosts_file=hosts,
        policy_file=policy,
        operator=operator,
        platforms=platforms,
    )
    xml_path = output_dir / "audit-report.xml"
    typer.echo(f"XML report: {xml_path}")
    typer.echo(f"Listeners: {len(ctx.listeners)} | Findings: {len(ctx.findings)}")

    if shutil.which("xsltproc"):
        html_path = output_dir / "audit-report.html"
        subprocess.run(
            [shutil.which("xsltproc"), "-o", str(html_path), str(_xslt_path()), str(xml_path)],
            check=True,
        )
        typer.echo(f"HTML report: {html_path}")
    else:
        typer.echo("Skipping HTML (install xsltproc for audit-report.html)")

    for art in ctx.rulesets:
        typer.echo(f"Ruleset: {art.path}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()


@app.command("init")
def init_firewall(
    output_dir: Path = typer.Option(Path("out-init"), "--output-dir", "-o"),
    answers: Optional[Path] = typer.Option(
        None,
        "--answers",
        help="YAML answers file (non-interactive)",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Require --answers; no prompts",
    ),
    platform: str = typer.Option(
        "auto",
        "--platform",
        help="auto, windows, nftables, or all",
    ),
    operator: str = typer.Option("home-lab", "--operator"),
) -> None:
    """Phase 1a: interactive wizard for secure initial firewall config."""
    from fw_audit.init.pipeline import run_init
    from fw_audit.init.wizard import load_or_wizard

    intent = load_or_wizard(answers, non_interactive)
    platforms: list[str] | None = None
    if platform == "windows":
        platforms = ["windows"]
    elif platform in ("nftables", "linux"):
        platforms = ["nftables"]
    elif platform == "all":
        platforms = ["windows", "nftables"]

    ctx = run_init(intent, output_dir, platforms=platforms, operator=operator)
    typer.echo(f"Init profile saved: {output_dir / 'init-profile.yaml'}")
    typer.echo(f"XML report: {output_dir / 'audit-report.xml'}")
    typer.echo(f"Planned rules: {len(ctx.listeners)} listeners | Findings: {len(ctx.findings)}")
    for art in ctx.rulesets:
        typer.echo(f"Ruleset: {art.path}")
    typer.echo(f"Read: {output_dir / 'INIT-README.txt'}")
