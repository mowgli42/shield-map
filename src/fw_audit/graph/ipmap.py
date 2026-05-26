"""Map IP addresses to inventory hosts."""

from __future__ import annotations

import ipaddress

from fw_audit.models import Host


def build_ip_to_host(hosts: dict[str, Host]) -> dict[str, Host]:
    mapping: dict[str, Host] = {}
    seen_ids: set[str] = set()
    for host in hosts.values():
        if not host.id.startswith("H") or host.id in seen_ids:
            continue
        seen_ids.add(host.id)
        for addr in host.addresses:
            mapping[addr] = host
    return mapping


def resolve_host(ip: str, ip_map: dict[str, Host]) -> Host | None:
    if ip in ip_map:
        return ip_map[ip]
    try:
        target = ipaddress.ip_address(ip)
        for addr, host in ip_map.items():
            try:
                net = ipaddress.ip_network(addr, strict=False)
                if target in net:
                    return host
            except ValueError:
                continue
    except ValueError:
        pass
    return None
