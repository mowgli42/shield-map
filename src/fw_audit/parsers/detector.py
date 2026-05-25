"""Auto-detect parser for netstat/ss/port list files."""

from __future__ import annotations

from pathlib import Path

from fw_audit.models import Connection, Listener
from fw_audit.parsers.connections import (
    parse_connections_netstat_linux,
    parse_connections_ss_linux,
    parse_connections_windows,
)
from fw_audit.parsers.netstat_linux import parse_netstat_linux
from fw_audit.parsers.netstat_windows import parse_netstat_windows
from fw_audit.parsers.port_list import parse_port_list
from fw_audit.parsers.ss_linux import parse_ss_linux


def detect_parser(text: str, path: Path) -> str:
    lower = text.lower()
    name = path.name.lower()
    if name.endswith(".csv"):
        return "port_list"
    if (
        "active connections" in lower
        and "local address" in lower
        and "foreign address" in lower
    ):
        return "netstat_windows"
    if name.startswith("ss") or ("netid" in lower and "local address:port" in lower):
        return "ss_linux"
    if "active internet connections" in lower or "proto recv-q" in lower:
        return "netstat_linux"
    if "tcp" in lower and "listening" in lower:
        return "netstat_windows"
    if "list" in lower and "local address:port" in lower:
        return "ss_linux"
    return "netstat_linux"


def parse_file(path: Path, host_id: str) -> tuple[list[Listener], list[Connection], str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    parser_name = detect_parser(text, path)
    source = str(path)

    if parser_name == "netstat_windows":
        listeners = parse_netstat_windows(text, host_id, source)
        connections = parse_connections_windows(text, host_id, source)
        return listeners, connections, parser_name
    if parser_name == "ss_linux":
        listeners = parse_ss_linux(text, host_id, source)
        connections = parse_connections_ss_linux(text, host_id, source)
        return listeners, connections, parser_name
    if parser_name == "port_list":
        return parse_port_list(text, host_id, source), [], parser_name
    listeners = parse_netstat_linux(text, host_id, source)
    connections = parse_connections_netstat_linux(text, host_id, source)
    return listeners, connections, parser_name
