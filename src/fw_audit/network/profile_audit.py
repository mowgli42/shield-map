"""Audit gateway, DNS, and interface posture (WiFi/BT/multi-homed)."""

from __future__ import annotations

from typing import Any

from fw_audit.models import Finding, Host, HostNetworkProfile, NetworkInterface, Severity


def audit_network_profile(
    profile: HostNetworkProfile,
    host: Host,
    policy: dict[str, Any],
) -> list[Finding]:
    findings: list[Finding] = []
    wl = policy.get("outbound_whitelist", {})
    trusted_gw = [str(g) for g in wl.get("trusted_gateways", [])]
    trusted_dns = [str(d) for d in wl.get("trusted_dns", [])]
    client_restrict = wl.get("client_interface_policy", {})

    if profile.default_gateway:
        if trusted_gw and profile.default_gateway not in trusted_gw:
            findings.append(
                Finding(
                    code="UNTRUSTED_DEFAULT_GATEWAY",
                    severity=Severity.HIGH,
                    message=f"Default gateway {profile.default_gateway} not in trusted_gateways",
                    remediation="Verify router or update policy trusted_gateways.",
                    host_id=host.id,
                )
            )
        gateways = {iface.gateway for iface in profile.interfaces if iface.gateway}
        if len(gateways) > 1:
            findings.append(
                Finding(
                    code="MULTIPLE_GATEWAYS",
                    severity=Severity.MEDIUM,
                    message=f"Multiple gateways detected: {', '.join(sorted(gateways))}",
                    remediation="Review multi-homed routing; restrict forwarding paths.",
                    host_id=host.id,
                )
            )

    for dns in profile.dns_servers:
        if trusted_dns and dns not in trusted_dns:
            findings.append(
                Finding(
                    code="UNTRUSTED_DNS",
                    severity=Severity.MEDIUM,
                    message=f"DNS server {dns} not in trusted_dns list",
                    remediation="Use organization/home DNS or update policy trusted_dns.",
                    host_id=host.id,
                )
            )

    up_ifaces = [i for i in profile.interfaces if i.state == "up" and i.kind != "loopback"]
    wifi_up = [i for i in up_ifaces if i.kind == "wifi"]
    bt_up = [i for i in up_ifaces if i.kind == "bluetooth"]

    if host.role in ("workstation", "client") or "client" in host.tags:
        if client_restrict.get("wifi_allowed") is False and wifi_up:
            findings.append(
                Finding(
                    code="WIFI_INTERFACE_UP",
                    severity=Severity.MEDIUM,
                    message=f"Wi-Fi interface(s) up: {', '.join(i.name for i in wifi_up)}",
                    remediation="Disable Wi-Fi on managed clients or set wifi_allowed: true in policy.",
                    host_id=host.id,
                )
            )
        if client_restrict.get("bluetooth_allowed") is False and bt_up:
            findings.append(
                Finding(
                    code="BLUETOOTH_INTERFACE_UP",
                    severity=Severity.LOW,
                    message=f"Bluetooth interface(s) up: {', '.join(i.name for i in bt_up)}",
                    remediation="Disable Bluetooth PAN when not required.",
                    host_id=host.id,
                )
            )

    virtual_up = [i for i in up_ifaces if i.kind == "virtual"]
    if len(up_ifaces) > 2 and (wifi_up or bt_up):
        findings.append(
            Finding(
                code="MULTI_NIC_ROUTING_RISK",
                severity=Severity.MEDIUM,
                message=(
                    f"{len(up_ifaces)} active NICs ({len(wifi_up)} Wi-Fi, "
                    f"{len(bt_up)} BT, {len(virtual_up)} virtual) — verify no bridge to untrusted networks"
                ),
                remediation="Document intended path; disable unused adapters.",
                host_id=host.id,
            )
        )

    return findings
