"""Generate Fail2ban jail.d drop-ins for allowed open ports.

Composes with host firewall rules (nftables backend preferred) rather than
re-implementing reactive banning inside fw-audit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fw_audit.generators.base import listeners_to_allow, ruleset_header
from fw_audit.models import Host, Listener

# Map classified service names to stock Fail2ban filters when available.
_STOCK_FILTERS: dict[str, str] = {
    "ssh": "sshd",
    "http": "nginx-http-auth",
    "https": "nginx-http-auth",
    "http-alt": "nginx-http-auth",
    "dns": "named-refused",
    "ftp": "vsftpd",
}


def _jail_name(ln: Listener) -> str:
    svc = (ln.service_name or ln.protocol).replace(" ", "-").lower()
    return f"fw-audit-{svc}-{ln.port}"


def _filter_for(ln: Listener) -> tuple[str, bool]:
    """Return (filter_name, known_stock_filter)."""
    svc = (ln.service_name or "").lower()
    if svc in _STOCK_FILTERS:
        return _STOCK_FILTERS[svc], True
    # Fall back to service name so operators can drop in a matching filter.
    fallback = svc or f"{ln.protocol}-{ln.port}"
    return fallback, False


def generate_fail2ban(
    host: Host,
    listeners: list[Listener],
    policy: dict[str, Any],
    output_path: Path,
    *,
    init_mode: bool = False,
) -> int:
    """Emit a jail.d drop-in for preferred/risky listeners still allowed by policy.

    Returns the number of jail sections written.
    """
    allow = listeners_to_allow(listeners, policy, init_mode=init_mode)
    inbound = [ln for ln in allow if ln.state != "planned-outbound"]

    lines = [
        ruleset_header("fail2ban-jail.d", host.hostname),
        f"# Mode: {'Phase 1a init baseline' if init_mode else 'netstat audit'}",
        "# Install: copy to /etc/fail2ban/jail.d/fw-audit.conf (Linux hosts)",
        "# Backend: nftables (banaction). Requires fail2ban + nftables.",
        "# REVIEW BEFORE APPLY — enable only jails whose filters match your daemons",
        "",
        "[DEFAULT]",
        "banaction = nftables-multiport",
        "banaction_allports = nftables-allports",
        "backend = systemd",
        "",
    ]

    jail_count = 0
    for ln in sorted(inbound, key=lambda x: (x.protocol, x.port)):
        name = _jail_name(ln)
        filt, known = _filter_for(ln)
        enabled = "true" if known else "false"
        comment = ln.service_name or f"{ln.protocol}/{ln.port}"
        lines.append(f"# {comment} ({ln.classification.value})")
        if not known:
            lines.append(
                f"# No stock Fail2ban filter for '{filt}' — "
                "add a filter under filter.d/ then set enabled = true"
            )
        lines.extend(
            [
                f"[{name}]",
                f"enabled = {enabled}",
                f"port = {ln.port}",
                f"protocol = {ln.protocol}",
                f"filter = {filt}",
                "maxretry = 5",
                "findtime = 10m",
                "bantime = 1h",
                "",
            ]
        )
        jail_count += 1

    if jail_count == 0:
        lines.append("# No preferred/risky listeners allowed by policy — nothing to jail.")
        lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return jail_count
