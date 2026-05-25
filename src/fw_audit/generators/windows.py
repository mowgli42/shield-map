"""Generate Windows Firewall PowerShell rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fw_audit.generators.base import listeners_to_allow, ruleset_header
from fw_audit.models import Classification, Host, Listener


def generate_windows(
    host: Host,
    listeners: list[Listener],
    policy: dict[str, Any],
    output_path: Path,
) -> int:
    allow = listeners_to_allow(listeners, policy)
    lines = [
        ruleset_header("windows", host.hostname),
        "# Requires: Run as Administrator in elevated PowerShell",
        "",
        "# Default deny inbound (Public profile)",
        "Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block",
        "Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Allow",
        "",
    ]

    rule_count = 0
    for ln in sorted(allow, key=lambda x: (x.protocol, x.port)):
        name = f"fw-audit-allow-{ln.protocol}-{ln.port}"
        lines.append(
            f"New-NetFirewallRule -DisplayName '{name}' -Direction Inbound "
            f"-Protocol {ln.protocol.upper()} -LocalPort {ln.port} -Action Allow "
            f"-Profile Private,Domain"
        )
        rule_count += 1

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

    lines.extend(
        [
            "",
            "# Implicit default deny on Public inbound (CIS 9.4)",
        ]
    )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return rule_count
