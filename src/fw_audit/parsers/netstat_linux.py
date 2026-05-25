"""Parse Linux netstat -tulpn export."""

from __future__ import annotations

from fw_audit.models import Listener
from fw_audit.parsers.common import normalize_protocol, parse_address_port


def parse_netstat_linux(
    text: str, host_id: str, source_file: str = ""
) -> list[Listener]:
    listeners: list[Listener] = []
    seen: set[tuple[str, str, int, str]] = set()

    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("Active Internet connections"):
            continue
        if line.startswith("Proto") or line.startswith("Netid"):
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        proto = normalize_protocol(parts[0])
        if proto not in ("tcp", "udp"):
            continue

        local_idx = 3 if parts[1].isdigit() else 2
        if local_idx >= len(parts):
            continue

        local = parts[local_idx]
        bind_addr, port = parse_address_port(local)
        if port == 0:
            continue

        process = parts[-1] if "/" in parts[-1] or parts[-1].startswith("-") else None

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
                process_name=process,
                observed_in_file=source_file,
                line_number=line_no,
            )
        )

    return listeners
