"""Generate nftables ruleset."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fw_audit.generators.base import listeners_to_allow, ruleset_header
from fw_audit.models import Classification, Host, Listener


def generate_nftables(
    host: Host,
    listeners: list[Listener],
    policy: dict[str, Any],
    output_path: Path,
) -> int:
    allow = listeners_to_allow(listeners, policy)
    lines = [
        ruleset_header("linux-nftables", host.hostname),
        "flush ruleset",
        "table inet fw_audit {",
        "  chain input {",
        "    type filter hook input priority 0; policy drop;",
        "    ct state established,related accept",
        "    iif lo accept",
    ]

    rule_count = 0
    for ln in sorted(allow, key=lambda x: (x.protocol, x.port)):
        lines.append(
            f"    {ln.protocol} dport {ln.port} accept  # {ln.service_name or 'allow'}"
        )
        rule_count += 1

    for ln in listeners:
        if ln.classification == Classification.UNSAFE:
            lines.append(
                f"    {ln.protocol} dport {ln.port} drop  # unsafe: block"
            )
            rule_count += 1

    lines.extend(
        [
            "    # default deny (CIS 9.4 / SC-7(5))",
            "  }",
            "}",
            "",
        ]
    )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return rule_count
