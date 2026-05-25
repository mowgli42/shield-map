"""Parse ESTABLISHED sessions from netstat/ss exports."""

from __future__ import annotations

from fw_audit.models import Connection
from fw_audit.parsers.common import normalize_protocol, parse_address_port


def parse_connections_windows(
    text: str, host_id: str, source_file: str = ""
) -> list[Connection]:
    connections: list[Connection] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("Active") or line.startswith("Proto"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = normalize_protocol(parts[0])
        if proto != "tcp":
            continue
        state = parts[3].upper()
        if state not in ("ESTABLISHED", "ESTAB"):
            continue
        local_addr, local_port = parse_address_port(parts[1])
        remote_addr, remote_port = parse_address_port(parts[2])
        if remote_port == 0:
            continue
        connections.append(
            Connection(
                host_id=host_id,
                protocol=proto,
                local_address=local_addr,
                local_port=local_port,
                remote_address=remote_addr,
                remote_port=remote_port,
                state=state,
                observed_in_file=source_file,
                line_number=line_no,
            )
        )
    return connections


def parse_connections_ss_linux(
    text: str, host_id: str, source_file: str = ""
) -> list[Connection]:
    connections: list[Connection] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("Netid") or line.startswith("State"):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        proto = normalize_protocol(parts[0])
        if proto != "tcp":
            continue
        state = parts[1].upper()
        if state not in ("ESTABLISHED", "ESTAB"):
            continue
        local_addr, local_port = parse_address_port(parts[4])
        remote_addr, remote_port = parse_address_port(parts[5])
        if remote_port == 0:
            continue
        connections.append(
            Connection(
                host_id=host_id,
                protocol=proto,
                local_address=local_addr,
                local_port=local_port,
                remote_address=remote_addr,
                remote_port=remote_port,
                state=state,
                observed_in_file=source_file,
                line_number=line_no,
            )
        )
    return connections


def parse_connections_netstat_linux(
    text: str, host_id: str, source_file: str = ""
) -> list[Connection]:
    connections: list[Connection] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or "ESTABLISHED" not in line.upper():
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = normalize_protocol(parts[0])
        if proto != "tcp":
            continue
        if parts[-2].upper() != "ESTABLISHED" and parts[3].upper() != "ESTABLISHED":
            continue
        local_idx = 3 if parts[1].isdigit() else 2
        foreign_idx = local_idx + 1
        if foreign_idx >= len(parts):
            continue
        local_addr, local_port = parse_address_port(parts[local_idx])
        remote_addr, remote_port = parse_address_port(parts[foreign_idx])
        if remote_port == 0:
            continue
        connections.append(
            Connection(
                host_id=host_id,
                protocol=proto,
                local_address=local_addr,
                local_port=local_port,
                remote_address=remote_addr,
                remote_port=remote_port,
                state="ESTABLISHED",
                observed_in_file=source_file,
                line_number=line_no,
            )
        )
    return connections
