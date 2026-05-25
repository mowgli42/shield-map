"""Load host inventory from YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from fw_audit.models import Host


def load_hosts(path: Path | None, default_hostname: str = "localhost") -> dict[str, Host]:
    if path is None or not path.is_file():
        host = Host(id="H001", hostname=default_hostname, zone="internal", role="server")
        return {host.id: host, default_hostname: host}

    with path.open(encoding="utf-8") as fh:
        data: dict[str, Any] = yaml.safe_load(fh) or {}

    hosts: dict[str, Host] = {}
    entries = data.get("hosts", data)
    if isinstance(entries, dict):
        items = entries.items()
    elif isinstance(entries, list):
        items = [(e.get("id", f"H{i:03d}"), e) for i, e in enumerate(entries, start=1)]
    else:
        items = []

    for key, entry in items:
        if not isinstance(entry, dict):
            continue
        hid = str(entry.get("id", key))
        hostname = str(entry.get("hostname", key))
        host = Host(
            id=hid,
            hostname=hostname,
            zone=str(entry.get("zone", "internal")),
            role=str(entry.get("role", "server")),
            os_family=str(entry.get("os_family", entry.get("os", "unknown"))),
            owner=str(entry.get("owner", "")),
            tags=[str(t) for t in entry.get("tags", [])],
        )
        hosts[hid] = host
        hosts[hostname] = host
        if isinstance(key, str) and key not in (hid, hostname):
            hosts[key] = host

    if not hosts:
        host = Host(id="H001", hostname=default_hostname, zone="internal", role="server")
        hosts[host.id] = host

    return hosts
