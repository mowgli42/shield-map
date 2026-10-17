"""Orchestrate Linux harden stages and emit distro-tailored scripts."""

from __future__ import annotations

import shutil
import socket
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from fw_audit.harden.capture import capture_listening_ports
from fw_audit.harden.distro import DistroFamily, HostDistro, detect_distro
from fw_audit.harden.scripts import (
    BACKUP_DNS,
    PRIMARY_DNS,
    write_harden_scripts,
)
from fw_audit.harden.stages import (
    STAGE_ORDER,
    STAGE_TITLES,
    StageId,
    StageResult,
    parse_stages,
)
from fw_audit.pipeline import run_audit

ConfirmFn = Callable[[str, bool], bool]
EchoFn = Callable[[str], None]


@dataclass
class HardenOptions:
    output_dir: Path
    input_path: Path | None = None
    hosts_file: Path | None = None
    policy_file: Path | None = None
    operator: str = "home-lab"
    apply: bool = False
    yes: bool = False
    install_opencanary: bool | None = None  # None → prompt when apply
    update_dns: bool | None = None
    install_drop: bool | None = None  # Spamhaus DROP; None → prompt when apply
    stages: list[StageId] = field(default_factory=lambda: list(STAGE_ORDER))
    hostname: str | None = None
    fw_audit_bin: str | None = None
    distro: HostDistro | None = None
    os_release_path: Path | None = None


@dataclass
class HardenResult:
    distro: HostDistro
    stages: list[StageResult] = field(default_factory=list)
    output_dir: Path | None = None
    scripts: dict[str, Path] = field(default_factory=dict)
    export_path: Path | None = None
    host_out: Path | None = None
    baseline_xml: Path | None = None


def _default_echo(msg: str) -> None:
    print(msg)


def _default_confirm(prompt: str, default: bool) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        raw = input(prompt + suffix).strip().lower()
    except EOFError:
        return default
    if not raw:
        return default
    return raw in ("y", "yes")


def _resolve_audit_root(export_path: Path | None, input_path: Path | None) -> Path:
    if export_path is not None:
        # .../imports/<host>/ss.txt → .../imports
        return export_path.parent.parent
    if input_path is None:
        raise ValueError("Pass --input or include the discover stage to capture ports")
    if input_path.is_file():
        return input_path.parent
    return input_path


def run_harden(
    options: HardenOptions,
    *,
    echo: EchoFn | None = None,
    confirm: ConfirmFn | None = None,
) -> HardenResult:
    """Execute selected harden stages; always write distro-tailored scripts after configure."""
    echo = echo or _default_echo
    confirm = confirm or _default_confirm

    distro = options.distro or detect_distro(options.os_release_path)
    out = options.output_dir
    out.mkdir(parents=True, exist_ok=True)
    result = HardenResult(distro=distro, output_dir=out)

    echo(
        f"Host: {distro.pretty_name} "
        f"(family={distro.family.value}, pkg={distro.package_manager})"
    )
    if distro.is_omarchy:
        echo("Detected Omarchy — using Arch (pacman) install scripts.")
    if not distro.supported:
        echo("Warning: unsupported distro; package-install scripts will refuse to run.")

    selected = set(options.stages or STAGE_ORDER)
    hostname = options.hostname or socket.gethostname().split(".")[0] or "localhost"
    export_path = out / "imports" / hostname / "ss.txt"
    host_out = out / hostname
    scripts_dir = out / "harden-scripts"
    dry_run = not options.apply

    # --- Stage: discover ---
    if StageId.DISCOVER in selected:
        echo(f"\n== Stage {StageId.DISCOVER.value}: {STAGE_TITLES[StageId.DISCOVER]} ==")
        try:
            if options.input_path:
                src = options.input_path
                if src.is_dir():
                    candidates = sorted(src.rglob("*.txt")) + sorted(src.rglob("*.log"))
                    if not candidates:
                        raise FileNotFoundError(f"No export files under {src}")
                    src = candidates[0]
                export_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, export_path)
                tool = "provided"
            else:
                export_path, tool = capture_listening_ports(export_path)
            result.export_path = export_path
            result.stages.append(
                StageResult(
                    stage=StageId.DISCOVER,
                    status="ok",
                    message=f"Captured listening ports via {tool}",
                    artifacts=[str(export_path)],
                )
            )
            echo(f"  → {export_path} ({tool})")
        except Exception as exc:  # noqa: BLE001 — stage boundary
            result.stages.append(
                StageResult(stage=StageId.DISCOVER, status="failed", message=str(exc))
            )
            echo(f"  ! Discover failed: {exc}")
            return result
    elif options.input_path:
        result.export_path = None

    # --- Stage: configure ---
    if StageId.CONFIGURE in selected:
        echo(f"\n== Stage {StageId.CONFIGURE.value}: {STAGE_TITLES[StageId.CONFIGURE]} ==")
        try:
            audit_root = _resolve_audit_root(result.export_path, options.input_path)
        except ValueError as exc:
            result.stages.append(
                StageResult(stage=StageId.CONFIGURE, status="failed", message=str(exc))
            )
            echo(f"  ! {exc}")
            return result

        ctx = run_audit(
            audit_root,
            out,
            hosts_file=options.hosts_file,
            policy_file=options.policy_file,
            operator=options.operator,
            platforms=["nftables", "fail2ban"],
            export_dot=False,
        )
        if not host_out.is_dir():
            for art in ctx.rulesets:
                p = Path(art.path)
                if p.name == "rules-nftables.conf":
                    host_out = p.parent
                    break
        result.host_out = host_out
        baseline = out / "audit-report.xml"
        result.baseline_xml = baseline
        arts = [str(a.path) for a in ctx.rulesets]
        arts.append(str(baseline))
        result.stages.append(
            StageResult(
                stage=StageId.CONFIGURE,
                status="ok",
                message=(
                    f"{len(ctx.listeners)} listeners → "
                    "firewall + Fail2ban + OpenCanary artifacts"
                ),
                artifacts=arts,
            )
        )
        echo(f"  → rules under {host_out}")
        echo(f"  → baseline {baseline}")

        fw_bin = (
            options.fw_audit_bin
            or shutil.which("shield-audit")
            or shutil.which("fw-audit")
            or "shield-audit"
        )
        result.scripts = write_harden_scripts(
            scripts_dir,
            distro,
            host_out=host_out,
            baseline_xml=baseline,
            fw_audit_bin=fw_bin,
        )
        echo(f"  → distro scripts: {scripts_dir} ({distro.family.value})")

    if not result.scripts:
        baseline = out / "audit-report.xml"
        if host_out.is_dir() and baseline.is_file():
            result.host_out = host_out
            result.baseline_xml = baseline
            fw_bin = (
                options.fw_audit_bin
                or shutil.which("shield-audit")
                or shutil.which("fw-audit")
                or "shield-audit"
            )
            result.scripts = write_harden_scripts(
                scripts_dir,
                distro,
                host_out=host_out,
                baseline_xml=baseline,
                fw_audit_bin=fw_bin,
            )

    def _want(flag: bool | None, prompt: str, default: bool) -> bool:
        if flag is not None:
            return flag
        if dry_run:
            # Scripts-only mode: record intended defaults without prompting.
            return default
        if options.yes:
            return True
        return confirm(prompt, default)

    def _confirm_apply(prompt: str, default: bool = True) -> bool:
        if dry_run:
            return True  # emit dry-run stage results
        if options.yes:
            return True
        return confirm(prompt, default)

    def _exec_named(stage: StageId, key: str) -> StageResult:
        script = result.scripts.get(key)
        if script is None:
            return StageResult(
                stage=stage,
                status="failed",
                message=f"Missing script {key}; run configure stage first",
            )
        if dry_run:
            return StageResult(
                stage=stage,
                status="dry-run",
                message=f"Scripts only — review and run {script.name}",
                artifacts=[str(script)],
            )
        if distro.family == DistroFamily.UNKNOWN and key == "install_deps":
            return StageResult(
                stage=stage,
                status="failed",
                message="Cannot install packages on unsupported distro",
            )
        proc = subprocess.run(["bash", str(script)], capture_output=True, text=True)
        text = ((proc.stdout or "") + (proc.stderr or "")).strip()
        return StageResult(
            stage=stage,
            status="ok" if proc.returncode == 0 else "failed",
            message=text or ("ok" if proc.returncode == 0 else f"exit {proc.returncode}"),
            artifacts=[str(script)],
            details={"returncode": proc.returncode},
        )

    def _tail(msg: str) -> str:
        lines = [ln for ln in msg.splitlines() if ln.strip()]
        return lines[-1] if lines else msg

    # --- Stage: firewall ---
    if StageId.FIREWALL in selected:
        echo(f"\n== Stage {StageId.FIREWALL.value}: {STAGE_TITLES[StageId.FIREWALL]} ==")
        if _confirm_apply("Apply nftables firewall rules now?", True):
            if options.apply:
                deps = _exec_named(StageId.FIREWALL, "install_deps")
                if deps.status == "failed":
                    result.stages.append(deps)
                    echo(f"  ! deps: {deps.message}")
            sr = _exec_named(StageId.FIREWALL, "apply_firewall")
            result.stages.append(sr)
            echo(f"  → {sr.status}: {_tail(sr.message)}")
        else:
            result.stages.append(
                StageResult(
                    stage=StageId.FIREWALL, status="skipped", message="Operator declined"
                )
            )
            echo("  → skipped")

    # --- Stage: fail2ban ---
    if StageId.FAIL2BAN in selected:
        echo(f"\n== Stage {StageId.FAIL2BAN.value}: {STAGE_TITLES[StageId.FAIL2BAN]} ==")
        if _confirm_apply("Install/setup Fail2ban for open ports?", True):
            if options.apply:
                deps = _exec_named(StageId.FAIL2BAN, "install_deps")
                if deps.status == "failed":
                    result.stages.append(deps)
            sr = _exec_named(StageId.FAIL2BAN, "setup_fail2ban")
            result.stages.append(sr)
            echo(f"  → {sr.status}: {_tail(sr.message)}")
        else:
            result.stages.append(
                StageResult(
                    stage=StageId.FAIL2BAN, status="skipped", message="Operator declined"
                )
            )
            echo("  → skipped")

    # --- Stage: opencanary (Y/n, default yes) ---
    if StageId.OPENCANARY in selected:
        echo(f"\n== Stage {StageId.OPENCANARY.value}: {STAGE_TITLES[StageId.OPENCANARY]} ==")
        want = _want(
            options.install_opencanary,
            "Install OpenCanary with defaults?",
            True,
        )
        if want:
            sr = _exec_named(StageId.OPENCANARY, "setup_opencanary")
            # In dry-run with default yes, still report dry-run rather than fake apply.
            if dry_run and options.install_opencanary is None:
                sr = StageResult(
                    stage=StageId.OPENCANARY,
                    status="dry-run",
                    message=(
                        "Would prompt Y/n then run 04-setup-opencanary.sh "
                        f"(defaults; DNS={PRIMARY_DNS} not related)"
                    ),
                    artifacts=[str(result.scripts.get("setup_opencanary", ""))],
                )
            result.stages.append(sr)
            echo(f"  → {sr.status}: {_tail(sr.message)}")
        else:
            result.stages.append(
                StageResult(
                    stage=StageId.OPENCANARY,
                    status="skipped",
                    message="Operator declined OpenCanary",
                )
            )
            echo("  → skipped")

    # --- Stage: dns (Y/n) ---
    if StageId.DNS in selected:
        echo(f"\n== Stage {StageId.DNS.value}: {STAGE_TITLES[StageId.DNS]} ==")
        want = _want(
            options.update_dns,
            f"Update DNS to filtered {PRIMARY_DNS} (backup {BACKUP_DNS})?",
            True,
        )
        if want:
            sr = _exec_named(StageId.DNS, "setup_dns")
            if dry_run and options.update_dns is None:
                sr = StageResult(
                    stage=StageId.DNS,
                    status="dry-run",
                    message=(
                        f"Would prompt Y/n then set DNS {PRIMARY_DNS} / {BACKUP_DNS} "
                        "via 05-setup-dns.sh"
                    ),
                    artifacts=[str(result.scripts.get("setup_dns", ""))],
                )
            result.stages.append(sr)
            echo(f"  → {sr.status}: {_tail(sr.message)}")
        else:
            result.stages.append(
                StageResult(
                    stage=StageId.DNS, status="skipped", message="Operator declined DNS"
                )
            )
            echo("  → skipped")

    # --- Stage: Spamhaus DROP (Y/n) ---
    if StageId.DROP in selected:
        echo(f"\n== Stage {StageId.DROP.value}: {STAGE_TITLES[StageId.DROP]} ==")
        want = _want(
            options.install_drop,
            "Enable Spamhaus DROP blocklist (nftables + daily refresh)?",
            True,
        )
        if want:
            sr = _exec_named(StageId.DROP, "setup_drop")
            if dry_run and options.install_drop is None:
                sr = StageResult(
                    stage=StageId.DROP,
                    status="dry-run",
                    message=(
                        "Would prompt Y/n then run 07-setup-drop.sh "
                        "(Spamhaus DROP → inet shield_drop; daily cron)"
                    ),
                    artifacts=[
                        str(result.scripts.get("setup_drop", "")),
                        str(result.scripts.get("drop_refresh", "")),
                    ],
                )
            result.stages.append(sr)
            echo(f"  → {sr.status}: {_tail(sr.message)}")
        else:
            result.stages.append(
                StageResult(
                    stage=StageId.DROP,
                    status="skipped",
                    message="Operator declined Spamhaus DROP",
                )
            )
            echo("  → skipped")

    # --- Stage: cron ---
    if StageId.CRON in selected:
        echo(f"\n== Stage {StageId.CRON.value}: {STAGE_TITLES[StageId.CRON]} ==")
        if _confirm_apply("Install shield-audit drift cron job?", True):
            sr = _exec_named(StageId.CRON, "setup_cron")
            result.stages.append(sr)
            echo(f"  → {sr.status}: {_tail(sr.message)}")
        else:
            result.stages.append(
                StageResult(stage=StageId.CRON, status="skipped", message="Operator declined")
            )
            echo("  → skipped")

    echo("\nHarden stages complete.")
    if dry_run:
        echo(f"Scripts written under {scripts_dir} (re-run with --apply to execute).")
    return result


__all__ = [
    "HardenOptions",
    "HardenResult",
    "run_harden",
    "parse_stages",
]
