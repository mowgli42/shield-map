"""Parse Windows netstat -ano export."""

from __future__ import annotations

from fw_audit.models import Listener
from fw_audit.parsers.common import normalize_protocol, parse_address_port


def parse_netstat_windows(
    text: str, host_id: str, source_file: str = ""
) -> list[Listener]:
    listeners: list[Listener] = []
    seen: set[tuple[str, str, int, str]] = set()

    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("Active Connections"):
            continue
        if line.startswith("Proto") or line.startswith("="):
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        proto = normalize_protocol(parts[0])
        if proto not in ("tcp", "udp"):
            continue

        local = parts[1]
        state = parts[3] if proto == "tcp" and len(parts) >= 5 else "LISTENING"

        if proto == "tcp" and state.upper() not in ("LISTENING", "LISTEN"):
            continue

        bind_addr, port = parse_address_port(local)
        if port == 0:
            continue

        key = (host_id, proto, port, bind_addr)
        if key in seen:
            continue
        seen.add(key)

        listeners.append(
            Listener(
                host_id=host_id,
                protocol=proto,
                port=port,
                bind_address=bind_addr,
                state="listening",
                observed_in_file=source_file,
                line_number=line_no,
            )
        )

    return listeners
