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


def _outbound_allow_lines(policy: dict[str, Any]) -> list[str]:
    wl = policy.get("outbound_whitelist", {})
    lines: list[str] = []
    for item in wl.get("approved_outbound_ports", []):
        if isinstance(item, dict):
            proto = str(item.get("proto", "tcp")).lower()
            port = int(item["port"])
            svc = item.get("service", f"port-{port}")
            lines.append(f"    {proto} dport {port} accept  # whitelist: {svc}")
    return lines


def generate_nftables(
    host: Host,
    listeners: list[Listener],
    policy: dict[str, Any],
    output_path: Path,
    *,
    init_mode: bool = False,
    strict_outbound: bool = False,
) -> int:
    allow = listeners_to_allow(listeners, policy, init_mode=init_mode)
    inbound = [ln for ln in allow if ln.state != "planned-outbound"]
    outbound = [ln for ln in listeners if ln.state == "planned-outbound"]

    mgmt_addrs: list[str] = []
    for ln in inbound:
        if len(ln.allowed_sources) > 1:
            mgmt_addrs = ln.allowed_sources
            break

    mode = "Phase 1a init baseline" if init_mode else "netstat audit"
    if strict_outbound:
        mode += " + outbound whitelist (default-deny egress)"

    lines = [
        ruleset_header("linux-nftables", host.hostname),
        f"# Mode: {mode}",
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

    if outbound or strict_outbound:
        lines.extend(
            [
                "  chain output {",
                "    type filter hook output priority 0; policy drop;",
                "    ct state established,related accept",
                "    oif lo accept",
            ]
        )
        if strict_outbound:
            lines.append("    # Outbound whitelist (CIS 12.4 egress control)")
            for ol in _outbound_allow_lines(policy):
                lines.append(ol)
                rule_count += 1
        for ln in sorted(outbound, key=lambda x: (x.protocol, x.port)):
            lines.append(
                f"    {ln.protocol} dport {ln.port} accept  # {ln.service_name} outbound"
            )
            rule_count += 1
        lines.append("  }")

    lines.extend(["}", ""])
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return rule_count
