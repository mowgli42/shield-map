"""Cross-zone flow policy checks."""

from __future__ import annotations

from typing import Any

from fw_audit.models import Finding, Flow, Host, Severity


def _pair_allowed(
    client_zone: str, server_zone: str, allowed_pairs: list[Any]
) -> bool:
    if client_zone == server_zone:
        return True
    for pair in allowed_pairs:
        if isinstance(pair, (list, tuple)) and len(pair) >= 2:
            if pair[0] == client_zone and pair[1] == server_zone:
                return True
        elif isinstance(pair, dict):
            if pair.get("from") == client_zone and pair.get("to") == server_zone:
                return True
            if pair.get("source") == client_zone and pair.get("dest") == server_zone:
                return True
    return False


def cross_zone_findings(
    flows: list[Flow],
    hosts: dict[str, Host],
    zone_policy: dict[str, Any],
) -> list[Finding]:
    allowed = zone_policy.get("allowed_zone_pairs", [])
    findings: list[Finding] = []

    for flow in flows:
        if flow.flow_kind != "session":
            continue
        if not flow.client_host_id or not flow.server_host_id:
            continue
        if flow.client_zone == flow.server_zone:
            continue
        if _pair_allowed(flow.client_zone, flow.server_zone, allowed):
            continue

        findings.append(
            Finding(
                code="CROSS_ZONE_UNRESTRICTED",
                severity=Severity.MEDIUM,
                message=(
                    f"Session {flow.client_zone}→{flow.server_zone} "
                    f"{flow.protocol}/{flow.port} ({flow.service_name}) "
                    f"not in allowed_zone_pairs"
                ),
                remediation=(
                    "Add zone pair to hosts.yaml allowed_zone_pairs or block with "
                    "firewall rules between segments."
                ),
                host_id=flow.server_host_id,
                listener_port=flow.port,
                listener_protocol=flow.protocol,
            )
        )
    return findings
