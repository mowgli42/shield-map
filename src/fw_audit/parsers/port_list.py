"""Parse CSV port inventory."""

from __future__ import annotations

import csv
import io

from fw_audit.models import Listener


def parse_port_list(text: str, host_id: str, source_file: str = "") -> list[Listener]:
    listeners: list[Listener] = []
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return listeners

    for line_no, row in enumerate(reader, start=2):
        proto = (row.get("protocol") or row.get("proto") or "tcp").strip().lower()
        port = int(row.get("port", 0))
        if port <= 0:
            continue
        bind = (row.get("bind_address") or row.get("address") or "0.0.0.0").strip()
        listeners.append(
            Listener(
                host_id=host_id,
                protocol=proto,
                port=port,
                bind_address=bind,
                state="listening",
                process_name=(row.get("process") or row.get("notes") or "").strip() or None,
                observed_in_file=source_file,
                line_number=line_no,
            )
        )
    return listeners
