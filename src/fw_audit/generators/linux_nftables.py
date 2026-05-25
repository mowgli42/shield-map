"""Generate nftables ruleset."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fw_audit.generators.base import listeners_to_allow, ruleset_header
from fw_audit.models import Classification, Host, Listener


def _source_match(sources: list[str]) -> str:
    if not sources:
        return ""
    if len(sources) == 1:
        return f"ip saddr {sources[0]} "
    return "ip saddr @mgmt_allow "


def generate_nftables(
    host: Host,
    listeners: list[Listener],
    policy: dict[str, Any],
    output_path: Path,
    *,
    init_mode: bool = False,
) -> int:
    allow = listeners_to_allow(listeners, policy, init_mode=init_mode)
    inbound = [ln for ln in allow if ln.state != "planned-outbound"]
    outbound = [ln for ln in listeners if ln.state == "planned-outbound"]

    mgmt_addrs: list[str] = []
    for ln in inbound:
        if len(ln.allowed_sources) > 1:
            mgmt_addrs = ln.allowed_sources
            break

    lines = [
        ruleset_header("linux-nftables", host.hostname),
        f"# Mode: {'Phase 1a init baseline' if init_mode else 'netstat audit'}",
        "flush ruleset",
        "table inet fw_audit {",
    ]

    if mgmt_addrs:
        lines.append("  set mgmt_allow {")
        lines.append("    type ipv4_addr")
        lines.append("    flags interval")
        lines.append("    elements = { " + ", ".join(mgmt_addrs) + " }")
        lines.append("  }")
        lines.append("")

    lines.extend(
        [
            "  chain input {",
            "    type filter hook input priority 0; policy drop;",
            "    ct state established,related accept",
            "    iif lo accept",
        ]
    )

    rule_count = 0
    for ln in sorted(inbound, key=lambda x: (x.protocol, x.port)):
        src = _source_match(ln.allowed_sources)
        comment = ln.service_name or "allow"
        lines.append(f"    {src}{ln.protocol} dport {ln.port} accept  # {comment}")
        rule_count += 1

    if not init_mode:
        for ln in listeners:
            if ln.classification == Classification.UNSAFE:
                lines.append(f"    {ln.protocol} dport {ln.port} drop  # unsafe")
                rule_count += 1

    lines.append("  }")

    if outbound:
        lines.extend(
            [
                "  chain output {",
                "    type filter hook output priority 0; policy drop;",
                "    ct state established,related accept",
                "    oif lo accept",
            ]
        )
        for ln in sorted(outbound, key=lambda x: (x.protocol, x.port)):
            lines.append(
                f"    {ln.protocol} dport {ln.port} accept  # {ln.service_name} outbound"
            )
            rule_count += 1
        lines.append("  }")

    lines.extend(["}", ""])
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return rule_count
