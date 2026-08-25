"""Parse host network profile exports (ipconfig, ip route, ip link)."""

from __future__ import annotations

import re

from fw_audit.models import HostNetworkProfile, NetworkInterface


def _iface_kind(name: str, description: str) -> str:
    text = f"{name} {description}".lower()
    if "loopback" in text or name.lower() in ("lo", "lo0"):
        return "loopback"
    if "bluetooth" in text or name.lower().startswith("bt") or "pan" in text:
        return "bluetooth"
    if "wi-fi" in text or "wifi" in text or "wlan" in text or "wireless" in text:
        return "wifi"
    if any(x in text for x in ("docker", "veth", "virbr", "br-", "tun", "tap")):
        return "virtual"
    if "ethernet" in text or name.lower().startswith(("eth", "en", "eno", "ens")):
        return "ethernet"
    return "unknown"


def parse_ipconfig_windows(text: str, host_id: str, source_file: str = "") -> HostNetworkProfile:
    profile = HostNetworkProfile(host_id=host_id, source_file=source_file)
    current: NetworkInterface | None = None
    gateways: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.endswith(":") and "adapter" in stripped.lower():
            if current:
                profile.interfaces.append(current)
            name = stripped.rstrip(":").replace("adapter", "").strip()
            current = NetworkInterface(name=name or "unknown", kind="unknown", state="unknown")
            continue

        if current is None:
            continue

        lower = stripped.lower()
        if lower.startswith("description") and "." in stripped:
            current.description = stripped.split(":", 1)[-1].strip()
            current.kind = _iface_kind(current.name, current.description)
        elif "media state" in lower or "media disconnected" in lower:
            current.state = "down" if "disconnected" in lower else "up"
        elif lower.startswith("ipv4 address") or lower.startswith("ip address"):
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
            if m:
                current.ipv4_addresses.append(m.group(1))
                if current.state == "unknown":
                    current.state = "up"
        elif "default gateway" in lower and "adapter" not in lower:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
            if m:
                gw = m.group(1)
                current.gateway = gw
                gateways.append(gw)
        elif lower.startswith("dns servers"):
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", stripped)
            if m and m.group(1) not in profile.dns_servers:
                profile.dns_servers.append(m.group(1))

    if current:
        profile.interfaces.append(current)

    if gateways:
        profile.default_gateway = gateways[0]
    return profile


def parse_linux_network_bundle(text: str, host_id: str, source_file: str = "") -> HostNetworkProfile:
    """Parse combined Linux export with # ip-route / # resolv.conf / # ip-link sections."""
    profile = HostNetworkProfile(host_id=host_id, source_file=source_file)
    section = "route"
    ifaces: dict[str, NetworkInterface] = {}

    for line in text.splitlines():
        if line.startswith("# ip-route") or line.startswith("# ip route"):
            section = "route"
            continue
        if line.startswith("# resolv") or line.startswith("# DNS"):
            section = "dns"
            continue
        if line.startswith("# ip-link") or line.startswith("# ip link"):
            section = "link"
            continue

        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if section == "route":
            if stripped.startswith("default via"):
                parts = stripped.split()
                if len(parts) >= 3:
                    profile.default_gateway = parts[2]
                if "dev" in parts:
                    dev = parts[parts.index("dev") + 1]
                    iface = ifaces.setdefault(
                        dev, NetworkInterface(name=dev, kind="unknown", state="up")
                    )
                    iface.gateway = profile.default_gateway
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)", stripped)
            if "dev" in stripped and m:
                dev = stripped.split("dev")[-1].split()[0]
                iface = ifaces.setdefault(
                    dev, NetworkInterface(name=dev, kind="unknown", state="up")
                )
                if m.group(1) not in iface.ipv4_addresses:
                    iface.ipv4_addresses.append(m.group(1))

        elif section == "dns":
            if stripped.startswith("nameserver"):
                ns = stripped.split()[1]
                if ns not in profile.dns_servers:
                    profile.dns_servers.append(ns)

        elif section == "link":
            m = re.match(r"^\d+:\s+([^:@]+)", stripped)
            if m:
                name = m.group(1)
                state = "up" if "UP" in stripped else "down"
                iface = ifaces.setdefault(
                    name, NetworkInterface(name=name, kind="unknown", state=state)
                )
                iface.kind = _iface_kind(name, stripped)

    profile.interfaces = list(ifaces.values())
    return profile


def detect_network_profile_parser(path_name: str, text: str) -> str | None:
    lower = text.lower()
    name = path_name.lower()
    if "ipconfig" in name or "windows ip configuration" in lower:
        return "ipconfig_windows"
    if "ip-route" in name or "ip link" in lower or "# ip-route" in lower:
        return "linux_bundle"
    if name in ("network.txt", "network-linux.txt", "network-profile.txt"):
        return "linux_bundle"
    if "default via" in lower and "nameserver" in lower:
        return "linux_bundle"
    return None


def parse_network_profile_file(
    text: str, host_id: str, path_name: str, source_file: str = ""
) -> HostNetworkProfile | None:
    kind = detect_network_profile_parser(path_name, text)
    if kind == "ipconfig_windows":
        return parse_ipconfig_windows(text, host_id, source_file)
    if kind == "linux_bundle":
        return parse_linux_network_bundle(text, host_id, source_file)
    return None
