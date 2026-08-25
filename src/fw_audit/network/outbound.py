"""Outbound internet usage and whitelist policy (CIS 12.4 / SC-7(5) egress)."""

from __future__ import annotations

import ipaddress
from typing import Any

from fw_audit.classify.engine import ClassificationEngine
from fw_audit.models import Classification, Connection, Finding, Host, OutboundServiceUse, Severity


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def build_outbound_service_uses(
    connections: list[Connection],
    host_id: str,
    engine: ClassificationEngine,
    policy: dict[str, Any],
) -> list[OutboundServiceUse]:
    """Summarize outbound sessions to non-private destinations."""
    uses: list[OutboundServiceUse] = []
    seen: set[tuple[str, str, str, int]] = set()
    approved_ports = _approved_outbound_set(policy)

    for conn in connections:
        if conn.host_id != host_id:
            continue
        if _is_private(conn.remote_address):
            continue

        proc = (conn.process_name or "unknown").strip()
        key = (proc, conn.protocol, conn.remote_address, conn.remote_port)
        if key in seen:
            continue
        seen.add(key)

        stub_port = conn.remote_port
        from fw_audit.models import Listener

        stub = Listener(
            host_id=host_id,
            protocol=conn.protocol,
            port=stub_port,
            bind_address=conn.remote_address,
        )
        classification = engine.classify_listener(stub, None)
        approved = _outbound_approved(conn, proc, policy, approved_ports, classification)

        uses.append(
            OutboundServiceUse(
                host_id=host_id,
                process_name=proc,
                protocol=conn.protocol,
                remote_address=conn.remote_address,
                remote_port=conn.remote_port,
                service_name=stub.service_name or f"port-{stub_port}",
                classification=classification,
                approved=approved,
                internet_facing=True,
            )
        )
    return uses


def _approved_outbound_set(policy: dict[str, Any]) -> set[tuple[str, int]]:
    wl = policy.get("outbound_whitelist", {})
    ports = wl.get("approved_outbound_ports", policy.get("approved_outbound_ports", []))
    result: set[tuple[str, int]] = set()
    for item in ports:
        if isinstance(item, dict):
            result.add((str(item.get("proto", "tcp")).lower(), int(item["port"])))
        elif isinstance(item, str) and "/" in item:
            p, port = item.split("/", 1)
            result.add((p.lower(), int(port)))
    return result


def _outbound_approved(
    conn: Connection,
    process: str,
    policy: dict[str, Any],
    approved_ports: set[tuple[str, int]],
    classification: Classification,
) -> bool:
    wl = policy.get("outbound_whitelist", {})
    if not wl.get("enforce", False):
        return True

    procs = [str(p).lower() for p in wl.get("approved_processes", [])]
    if procs and process.lower() in procs:
        return True

    if (conn.protocol.lower(), conn.remote_port) in approved_ports:
        return True
    if classification == Classification.PREFERRED:
        return True
    return False


def analyze_outbound_whitelist(
    uses: list[OutboundServiceUse],
    policy: dict[str, Any],
) -> list[Finding]:
    wl = policy.get("outbound_whitelist", {})
    if not wl.get("enforce", False):
        return []

    findings: list[Finding] = []
    for use in uses:
        if use.approved:
            continue
        findings.append(
            Finding(
                code="UNAPPROVED_OUTBOUND",
                severity=Severity.HIGH,
                message=(
                    f"Process '{use.process_name}' outbound {use.protocol}/"
                    f"{use.remote_port} to {use.remote_address} ({use.service_name}) "
                    f"not on outbound whitelist"
                ),
                remediation=(
                    "Add to policy outbound_whitelist.approved_outbound_ports or "
                    "approved_processes, or block in host firewall output chain."
                ),
                host_id=use.host_id,
                listener_port=use.remote_port,
                listener_protocol=use.protocol,
            )
        )
    return findings
