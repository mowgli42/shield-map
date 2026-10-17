"""User-facing console entry points: shield-map, shield-up, shield-audit.

These wrap the Typer CLI so pip-installed binaries match the root bash scripts.
The Python package remains ``fw_audit`` for library consumers.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import typer

from fw_audit import __version__


def _warn_if_legacy_argv() -> None:
    name = Path(sys.argv[0]).name
    if name in ("fw-audit", "fw_audit"):
        typer.echo(
            "note: 'fw-audit' is deprecated; prefer shield-map / shield-up / shield-audit",
            err=True,
        )


# ---------------------------------------------------------------------------
# shield-map — capture / ingest → rules + reports (all-in-one path)
# ---------------------------------------------------------------------------

shield_map_app = typer.Typer(
    name="shield-map",
    help=(
        "Capture open ports (or accept an export) and generate deny-by-default "
        "firewall rulesets, Fail2ban jail.d, OpenCanary suggestions, and audit XML."
    ),
    add_completion=False,
    invoke_without_command=True,
)


@shield_map_app.callback(invoke_without_command=True)
def shield_map_main(
    ctx: typer.Context,
    input_path: Path | None = typer.Option(
        None,
        "--input",
        "-i",
        help="Existing netstat/ss export or imports directory (skip live capture)",
    ),
    output_dir: Path = typer.Option(Path("out"), "--output-dir", "-o"),
    hosts: Path | None = typer.Option(None, "--hosts"),
    policy: Path | None = typer.Option(None, "--policy"),
    platform: str = typer.Option(
        "all",
        "--platform",
        help="windows, nftables, cisco, fail2ban, or all",
    ),
    operator: str = typer.Option("home-lab", "--operator"),
    export_dot: bool = typer.Option(True, "--dot/--no-dot"),
    hostname: str | None = typer.Option(None, "--hostname"),
    version: bool = typer.Option(False, "--version", help="Show version and exit"),
) -> None:
    """Live capture (default) or --input export → all-in-one artifacts."""
    if version:
        typer.echo(f"shield-map {__version__} (fw-audit package)")
        raise typer.Exit(0)
    if ctx.invoked_subcommand is not None:
        return

    from fw_audit.cli import _echo_artifact, _platforms_from_flag, _xslt_path
    from fw_audit.harden.capture import capture_listening_ports
    from fw_audit.pipeline import run_audit

    path = input_path
    if path is None:
        host = hostname or socket.gethostname().split(".")[0] or "localhost"
        export = output_dir / "imports" / host / "ss.txt"
        typer.echo(f"Capturing listening ports → {export}")
        capture_listening_ports(export)
        path = export.parent.parent  # imports/

    platforms = _platforms_from_flag(platform)
    ctx_audit = run_audit(
        path,
        output_dir,
        hosts_file=hosts,
        policy_file=policy,
        operator=operator,
        platforms=platforms,
        export_dot=export_dot,
    )
    xml_path = output_dir / "audit-report.xml"
    typer.echo(f"XML report: {xml_path}")
    typer.echo(f"Ports/protocols: {output_dir / 'ports-protocols.json'}")
    typer.echo(
        f"Listeners: {len(ctx_audit.listeners)} | Findings: {len(ctx_audit.findings)}"
    )
    if shutil.which("xsltproc"):
        html_path = output_dir / "audit-report.html"
        subprocess.run(
            [shutil.which("xsltproc"), "-o", str(html_path), str(_xslt_path()), str(xml_path)],
            check=True,
        )
        typer.echo(f"HTML report: {html_path}")
    for art in ctx_audit.rulesets:
        _echo_artifact(art)


def shield_map() -> None:
    shield_map_app()


# ---------------------------------------------------------------------------
# shield-up — Linux harden composition
# ---------------------------------------------------------------------------

def shield_up() -> None:
    """Linux harden front door (same stages as ``fw-audit harden``)."""
    from fw_audit.cli import harden_cmd

    app = typer.Typer(
        name="shield-up",
        help=(
            "Linux harden: discover → nftables → Fail2ban → optional OpenCanary → "
            "optional DNS → optional Spamhaus DROP → shield-audit cron."
        ),
        add_completion=False,
        invoke_without_command=True,
    )

    @app.callback(invoke_without_command=True)
    def _run(
        output_dir: Path = typer.Option(Path("out-harden"), "--output-dir", "-o"),
        input_path: Path | None = typer.Option(None, "--input", "-i"),
        hosts: Path | None = typer.Option(None, "--hosts"),
        policy: Path | None = typer.Option(None, "--policy"),
        operator: str = typer.Option("home-lab", "--operator"),
        apply: bool = typer.Option(False, "--apply/--scripts-only"),
        yes: bool = typer.Option(False, "--yes", "-y"),
        opencanary: bool | None = typer.Option(None, "--opencanary/--no-opencanary"),
        dns: bool | None = typer.Option(None, "--dns/--no-dns"),
        drop: bool | None = typer.Option(None, "--drop/--no-drop"),
        stages: str | None = typer.Option(None, "--stages"),
        hostname: str | None = typer.Option(None, "--hostname"),
        version: bool = typer.Option(False, "--version"),
    ) -> None:
        if version:
            typer.echo(f"shield-up {__version__} (fw-audit package)")
            raise typer.Exit(0)
        harden_cmd(
            output_dir=output_dir,
            input_path=input_path,
            hosts=hosts,
            policy=policy,
            operator=operator,
            apply=apply,
            yes=yes,
            opencanary=opencanary,
            dns=dns,
            drop=drop,
            stages=stages,
            hostname=hostname,
        )

    app()


# ---------------------------------------------------------------------------
# shield-audit — drift check vs baseline
# ---------------------------------------------------------------------------

def shield_audit() -> None:
    audit_app = typer.Typer(
        name="shield-audit",
        help="Compare current host listeners to a shield-map / shield-up baseline XML.",
        add_completion=False,
        invoke_without_command=True,
    )

    @audit_app.callback(invoke_without_command=True)
    def _run(
        baseline: Path | None = typer.Option(
            None,
            "--baseline",
            "-b",
            help=(
                "Baseline audit-report.xml "
                "(default: /var/lib/shield-map/baseline-audit-report.xml)"
            ),
        ),
        output_dir: Path = typer.Option(
            Path("/var/lib/shield-map/current"),
            "--output-dir",
            "-o",
            help="Where to write the current report and drift summary",
        ),
        input_path: Path | None = typer.Option(
            None,
            "--input",
            "-i",
            help="Existing export instead of live capture",
        ),
        format: str = typer.Option("text", "--format", "-f", help="text or json"),
        version: bool = typer.Option(False, "--version"),
    ) -> None:
        if version:
            typer.echo(f"shield-audit {__version__} (fw-audit package)")
            raise typer.Exit(0)

        from fw_audit.diff import diff_paths
        from fw_audit.harden.capture import capture_listening_ports
        from fw_audit.pipeline import run_audit

        default_baseline = Path("/var/lib/shield-map/baseline-audit-report.xml")
        legacy_baseline = Path("/var/lib/fw-audit/baseline-audit-report.xml")
        base = baseline
        if base is None:
            if default_baseline.is_file():
                base = default_baseline
            elif legacy_baseline.is_file():
                base = legacy_baseline
            else:
                typer.echo(
                    "No baseline found. Pass --baseline or run shield-up first "
                    f"(looked for {default_baseline}).",
                    err=True,
                )
                raise typer.Exit(2)

        if not base.is_file():
            typer.echo(f"Baseline not found: {base}", err=True)
            raise typer.Exit(2)

        output_dir.mkdir(parents=True, exist_ok=True)
        if input_path is None:
            host = socket.gethostname().split(".")[0] or "localhost"
            export = output_dir / "imports" / host / "ss.txt"
            try:
                capture_listening_ports(export)
            except RuntimeError as exc:
                typer.echo(str(exc), err=True)
                raise typer.Exit(2) from exc
            audit_root = export.parent.parent
        else:
            audit_root = input_path

        run_audit(
            audit_root,
            output_dir,
            platforms=[],
            export_dot=False,
        )
        current_xml = output_dir / "audit-report.xml"
        summary_path = output_dir / "drift-summary.txt"

        try:
            result = diff_paths(base, current_xml)
        except (ET.ParseError, ValueError, OSError) as exc:
            typer.echo(f"Failed to diff reports: {exc}", err=True)
            raise typer.Exit(2) from exc

        text = result.to_json() if format == "json" else result.to_text()
        summary_path.write_text(text + "\n", encoding="utf-8")
        typer.echo(text)
        typer.echo(f"Drift summary: {summary_path}", err=True)
        typer.echo(f"Current report: {current_xml}", err=True)
        typer.echo(f"Baseline: {base}", err=True)

        if result.drift_detected:
            typer.echo("shield-audit: configuration drift detected", err=True)
            raise typer.Exit(1)
        typer.echo("shield-audit: no drift", err=True)

    audit_app()


def deprecated_fw_audit() -> None:
    """Legacy ``fw-audit`` console script with deprecation notice."""
    _warn_if_legacy_argv()
    from fw_audit.cli import app

    app()
