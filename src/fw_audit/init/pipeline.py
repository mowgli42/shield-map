"""Phase 1a: generate secure baseline rules from host intent (no netstat required)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fw_audit.classify.engine import ClassificationEngine, load_policy
from fw_audit.graph.flows import build_flows
from fw_audit.init.profile import (
    build_listeners_from_intent,
    host_from_intent,
    save_intent,
)
from fw_audit.init.profile import HostIntent
from fw_audit.models import AuditContext, RulesetArtifact
from fw_audit.report.xml_builder import write_audit_xml


def run_init(
    intent: HostIntent,
    output_dir: Path,
    platforms: list[str] | None = None,
    operator: str = "home-lab",
) -> AuditContext:
    from fw_audit.generators.linux_nftables import generate_nftables
    from fw_audit.generators.windows import generate_windows

    output_dir.mkdir(parents=True, exist_ok=True)
    host = host_from_intent(intent)
    listeners, intent_policy = build_listeners_from_intent(intent, host.id)
    policy = load_policy()
    policy["approved_risky"] = intent_policy.get("approved_risky", [])
    policy["init_baseline"] = True
    policy["version"] = intent_policy.get("version", "1.0-init")
    policy["mgmt_cidr"] = intent.mgmt_cidr
    for ln in listeners:
        pass  # keep planned classifications

    engine = ClassificationEngine(policy)
    hosts_map = {host.id: host}
    ctx = AuditContext(
        hosts=[host],
        listeners=listeners,
        policy_version=str(policy.get("version", "1.0-init")),
        operator=operator,
    )
    ctx.findings = _findings_for_init(listeners, hosts_map, engine)
    ctx.flows = build_flows(listeners, hosts_map)
    ctx.warnings.append(
        "Phase 1a init profile: review rules before apply. No netstat input was used."
    )

    save_intent(intent, output_dir / "init-profile.yaml")

    host_out = output_dir / host.hostname
    host_out.mkdir(parents=True, exist_ok=True)
    platforms = platforms or _default_platforms(intent.os_family)

    if "windows" in platforms:
        path = host_out / "rules-windows.ps1"
        count = generate_windows(host, listeners, policy, path, init_mode=True)
        ctx.rulesets.append(_artifact("windows", "powershell", path, host.id, count))

    if "nftables" in platforms:
        path = host_out / "rules-nftables.conf"
        count = generate_nftables(host, listeners, policy, path, init_mode=True)
        ctx.rulesets.append(_artifact("linux", "nftables", path, host.id, count))

    write_audit_xml(ctx, output_dir / "audit-report.xml")
    _write_readme(output_dir, intent)
    return ctx


def _default_platforms(os_family: str) -> list[str]:
    if os_family == "windows":
        return ["windows"]
    if os_family == "linux":
        return ["nftables"]
    return ["windows", "nftables"]


def _artifact(platform: str, fmt: str, path: Path, host_id: str, count: int) -> RulesetArtifact:
    return RulesetArtifact(
        platform=platform,
        format=fmt,
        path=str(path),
        default_deny=True,
        rule_count=count,
        host_id=host_id,
    )


def _write_readme(output_dir: Path, intent: HostIntent) -> None:
    readme = output_dir / "INIT-README.txt"
    lines = [
        "fw-audit Phase 1a — Secure initial firewall configuration",
        "=" * 50,
        f"Host: {intent.hostname} ({intent.host_type})",
        f"Generated from: init-profile.yaml",
        "",
        "CIS 9.4 / NIST SC-7(5): default-deny inbound; only selected services allowed.",
        "Management CIDR restricts admin and file-share ports where applicable.",
        "",
        "NEXT STEPS:",
        "1. Review rules-*.ps1 or rules-nftables.conf",
        "2. Apply during a maintenance window",
        "3. Re-run 'fw-audit all-in-one' with netstat export to compare live vs plan",
        "",
        "DO NOT apply blindly if you have existing custom firewall rules.",
    ]
    readme.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _findings_for_init(listeners, hosts_map, engine):
    """Findings for init: skip expected public-bind / unapproved noise."""
    findings = engine.apply_to_listeners(listeners, hosts_map)
    filtered = []
    for f in findings:
        if f.code == "RISKY_PORT_PUBLIC_BIND":
            ln = next(
                (
                    l
                    for l in listeners
                    if l.port == f.listener_port and l.protocol == f.listener_protocol
                ),
                None,
            )
            if ln and (ln.allowed_sources or ln.observed_in_file == "init-wizard"):
                continue
        if f.code == "RISKY_PORT_UNAPPROVED":
            continue
        filtered.append(f)
    return filtered
