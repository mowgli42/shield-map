"""Shared parsing helpers."""

from __future__ import annotations

import re


def parse_address_port(value: str) -> tuple[str, int]:
    """Parse '192.168.1.1:443' or '[::1]:443' or '0.0.0.0:*'."""
    value = value.strip()
    if value.endswith(":*"):
        addr = value[:-2]
        return addr, 0

    if value.startswith("["):
        match = re.match(r"^\[([^\]]+)\]:(\d+|\*)$", value)
        if match:
            port = 0 if match.group(2) == "*" else int(match.group(2))
            return match.group(1), port

    if ":" in value:
        host, _, port_str = value.rpartition(":")
        if port_str == "*":
            return host, 0
        return host, int(port_str)

    return value, 0


def normalize_protocol(proto: str) -> str:
    p = proto.strip().lower()
    if p in ("tcp", "tcpv4", "tcpv6"):
        return "tcp"
    if p in ("udp", "udpv4", "udpv6"):
        return "udp"
    return p
