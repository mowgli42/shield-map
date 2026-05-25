"""Generate Windows Firewall PowerShell rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fw_audit.generators.base import listeners_to_allow, ruleset_header
from fw_audit.models import Classification, Host, Listener


def _remote_address_arg(sources: list[str]) -> str:
    if not sources:
        return ""
    addrs = ",".join(sources)
    return f" -RemoteAddress {addrs}"


def generate_windows(
    host: Host,
    listeners: list[Listener],
    policy: dict[str, Any],
    output_path: Path,
    *,
    init_mode: bool = False,
) -> int:
    allow = listeners_to_allow(listeners, policy, init_mode=init_mode)
    header_note = "Phase 1a init baseline" if init_mode else "netstat audit"
    lines = [
        ruleset_header("windows", host.hostname),
        f"# Mode: {header_note}",
        "# Requires: Run as Administrator in elevated PowerShell",
        "",
        "Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block",
        "Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block",
        "Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block",
        "Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Allow",
        "",
    ]

    rule_count = 3
    inbound = [ln for ln in allow if ln.state != "planned-outbound"]

    for ln in sorted(inbound, key=lambda x: (x.protocol, x.port)):
        name = f"fw-audit-allow-{ln.service_name or ln.protocol}-{ln.port}"
        remote = _remote_address_arg(ln.allowed_sources)
        comment = f"  # {ln.service_name}" if ln.service_name else ""
        lines.append(
            f"New-NetFirewallRule -DisplayName '{name}' -Direction Inbound "
            f"-Protocol {ln.protocol.upper()} -LocalPort {ln.port} -Action Allow "
            f"-Profile Private,Domain{remote}{comment}"
        )
        rule_count += 1

    if init_mode:
        lines.append("")
        lines.append("# Block same risky ports on Public profile (defense in depth)")
        for ln in inbound:
            if ln.classification == Classification.RISKY:
                name = f"fw-audit-block-public-{ln.service_name or ln.protocol}-{ln.port}"
                lines.append(
                    f"New-NetFirewallRule -DisplayName '{name}' -Direction Inbound "
                    f"-Protocol {ln.protocol.upper()} -LocalPort {ln.port} -Action Block "
                    f"-Profile Public"
                )
                rule_count += 1
    else:
        for ln in listeners:
            if ln.classification == Classification.UNSAFE:
                name = f"fw-audit-block-{ln.protocol}-{ln.port}"
                lines.append(
                    f"New-NetFirewallRule -DisplayName '{name}' -Direction Inbound "
                    f"-Protocol {ln.protocol.upper()} -LocalPort {ln.port} -Action Block "
                    f"-Profile Any"
                )
                rule_count += 1
            elif ln.classification == Classification.RISKY:
                name = f"fw-audit-block-public-{ln.protocol}-{ln.port}"
                lines.append(
                    f"New-NetFirewallRule -DisplayName '{name}' -Direction Inbound "
                    f"-Protocol {ln.protocol.upper()} -LocalPort {ln.port} -Action Block "
                    f"-Profile Public"
                )
                rule_count += 1

    lines.extend(["", "# Default deny inbound (CIS 9.4 / SC-7(5))"])
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return rule_count
