"""Generate Cisco IOS extended ACL snippet."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fw_audit.generators.base import listeners_to_allow, ruleset_header
from fw_audit.models import Classification, Host, Listener


def _acl_comment(host: Host) -> list[str]:
    return [
        f"! ACL for host {host.hostname} zone={host.zone}",
        "! Place on interface facing clients (adjust direction as needed)",
        f"ip access-list extended FW_AUDIT_{host.hostname.upper().replace('-', '_')}",
    ]


def generate_cisco_ios(
    host: Host,
    listeners: list[Listener],
    policy: dict[str, Any],
    output_path: Path,
    *,
    init_mode: bool = False,
) -> int:
    allow = listeners_to_allow(listeners, policy, init_mode=init_mode)
    inbound = [ln for ln in allow if ln.state != "planned-outbound"]
    mgmt = policy.get("mgmt_cidr", "192.168.0.0/16")

    lines = [
        ruleset_header("cisco-ios", host.hostname),
        * _acl_comment(host),
        " remark CIS 9.4 default deny at end",
        " remark NIST SC-7(5) allow-by-exception",
    ]
    rule_count = 0

    for ln in sorted(inbound, key=lambda x: (x.protocol, x.port)):
        proto = "tcp" if ln.protocol == "tcp" else "udp"
        svc = ln.service_name or str(ln.port)
        if ln.allowed_sources:
            src = ln.allowed_sources[0]
            lines.append(
                f" permit {proto} {src} any eq {ln.port} remark {svc}"
            )
        elif ln.classification == Classification.PREFERRED and ln.port in (443, 22):
            lines.append(f" permit {proto} {mgmt} any eq {ln.port} remark {svc}")
        else:
            lines.append(
                f" permit {proto} {mgmt} any eq {ln.port} remark {svc}-restricted"
            )
        rule_count += 1

    for ln in listeners:
        if ln.classification == Classification.UNSAFE:
            lines.append(
                f" deny {ln.protocol} any any eq {ln.port} remark block-{ln.service_name}"
            )
            rule_count += 1

    lines.extend(
        [
            " deny ip any any",
            "!",
        ]
    )
    rule_count += 1

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return rule_count
