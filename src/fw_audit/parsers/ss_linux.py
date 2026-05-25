"""Parse Linux ss -tulpn export."""

from __future__ import annotations

import re

from fw_audit.models import Listener
from fw_audit.parsers.common import normalize_protocol, parse_address_port

_PROCESS_RE = re.compile(r'users:\(\("([^"]+)"')


def parse_ss_linux(text: str, host_id: str, source_file: str = "") -> list[Listener]:
    listeners: list[Listener] = []
    seen: set[tuple[str, str, int, str]] = set()

    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("Netid") or line.startswith("State"):
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        proto = normalize_protocol(parts[0])
        if proto not in ("tcp", "udp"):
            continue

        state = parts[1].upper()
        if state not in ("LISTEN", "UNCONN"):
            continue

        local = parts[4]
        bind_addr, port = parse_address_port(local)
        if port == 0:
            continue

        proc_match = _PROCESS_RE.search(line)
        process = proc_match.group(1) if proc_match else None

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
