"""Suggest OpenCanary deception config for unused high-value ports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fw_audit.generators.base import listeners_to_allow
from fw_audit.models import Classification, Host, Listener

# Classification catalog ports that OpenCanary can emulate (module name).
# Port values follow fw-audit defaults.yaml (VNC uses 5900, not OpenCanary's 5000).
_OPENCANARY_BY_PORT: dict[tuple[str, int], str] = {
    ("tcp", 21): "ftp",
    ("tcp", 22): "ssh",
    ("tcp", 23): "telnet",
    ("tcp", 80): "http",
    ("tcp", 443): "https",
    ("tcp", 8080): "httpproxy",
    ("tcp", 1433): "mssql",
    ("tcp", 3306): "mysql",
    ("tcp", 3389): "rdp",
    ("tcp", 5900): "vnc",
    ("tcp", 6379): "redis",
    ("tcp", 27017): "mongodb",
    ("udp", 161): "snmp",
}

# Role-model ports treated as required even when not yet observed listening.
_ROLE_REQUIRED: dict[str, set[tuple[str, int]]] = {
    "workstation": set(),
    "client": set(),
    "server": {("tcp", 22)},
    "web": {("tcp", 443), ("tcp", 80)},
    "database": {("tcp", 5432), ("tcp", 3306)},
    "router": {("tcp", 22)},
}


def _catalog_high_value_ports(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Return catalog entries that map to an OpenCanary module."""
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for category, items in policy.get("categories", {}).items():
        for item in items:
            proto = str(item.get("proto", "tcp")).lower()
            port = int(item["port"])
            key = (proto, port)
            if key in seen or key not in _OPENCANARY_BY_PORT:
                continue
            seen.add(key)
            entries.append(
                {
                    "proto": proto,
                    "port": port,
                    "service": str(item.get("service", f"port-{port}")),
                    "classification": category,
                    "module": _OPENCANARY_BY_PORT[key],
                }
            )
    return entries


def _in_use_ports(listeners: list[Listener]) -> set[tuple[str, int]]:
    return {
        (ln.protocol.lower(), ln.port)
        for ln in listeners
        if ln.state != "planned-outbound"
    }


def _required_ports(
    host: Host,
    listeners: list[Listener],
    policy: dict[str, Any],
) -> set[tuple[str, int]]:
    """Ports preferred/required for this host — excluded from canary suggestions."""
    required = set(_ROLE_REQUIRED.get(host.role.lower(), set()))
    required |= _in_use_ports(listeners)
    for ln in listeners_to_allow(listeners, policy):
        if ln.state == "planned-outbound":
            continue
        required.add((ln.protocol.lower(), ln.port))
    for ln in listeners:
        if ln.classification == Classification.PREFERRED and ln.state != "planned-outbound":
            required.add((ln.protocol.lower(), ln.port))
    return required


def suggest_canary_ports(
    host: Host,
    listeners: list[Listener],
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    High-value catalog ports that are unused and not required by role/allow-set.

    Candidates for low-interaction OpenCanary listeners. SnarkSentinel (or an
    operator) owns process lifecycle and log ingestion.
    """
    required = _required_ports(host, listeners, policy)
    suggestions: list[dict[str, Any]] = []
    for entry in _catalog_high_value_ports(policy):
        key = (entry["proto"], entry["port"])
        if key in required:
            continue
        suggestions.append(
            {
                **entry,
                "reason": f"unused high-value port; not required for role={host.role}",
            }
        )
    return sorted(suggestions, key=lambda e: (e["proto"], e["port"]))


def build_opencanary_conf(
    host: Host,
    suggestions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Minimal `.opencanary.conf` enabling only suggested modules."""
    conf: dict[str, Any] = {
        "device.node_id": f"fw-audit-{host.hostname}",
        "ip.ignorelist": [],
        "logtype.ignorelist": [],
        "logger": {
            "class": "PyLogger",
            "kwargs": {
                "formatters": {"plain": {"format": "%(message)s"}},
                "handlers": {
                    "console": {
                        "class": "logging.StreamHandler",
                        "stream": "ext://sys.stdout",
                    },
                    "file": {
                        "class": "logging.FileHandler",
                        "filename": "/var/tmp/opencanary.log",
                    },
                },
            },
        },
    }
    enabled_modules: dict[str, int] = {}
    for item in suggestions:
        enabled_modules[item["module"]] = int(item["port"])

    for module, port in sorted(enabled_modules.items()):
        conf[f"{module}.enabled"] = True
        conf[f"{module}.port"] = port

    return conf


def generate_opencanary(
    host: Host,
    listeners: list[Listener],
    policy: dict[str, Any],
    output_dir: Path,
) -> tuple[int, Path, Path]:
    """
    Write suggested OpenCanary config and port list under *output_dir*.

    Returns (suggestion_count, conf_path, ports_path).
    """
    suggestions = suggest_canary_ports(host, listeners, policy)
    output_dir.mkdir(parents=True, exist_ok=True)

    conf_path = output_dir / ".opencanary.conf"
    ports_path = output_dir / "opencanary-ports.json"

    conf = build_opencanary_conf(host, suggestions)
    conf_path.write_text(json.dumps(conf, indent=2) + "\n", encoding="utf-8")

    port_list = {
        "host": host.hostname,
        "host_id": host.id,
        "role": host.role,
        "zone": host.zone,
        "note": (
            "Suggested OpenCanary deception listeners for unused high-value ports. "
            "Review before enable; SnarkSentinel may own lifecycle/log ingestion."
        ),
        "ports": [
            {
                "proto": s["proto"],
                "port": s["port"],
                "module": s["module"],
                "service": s["service"],
                "classification": s["classification"],
                "reason": s["reason"],
            }
            for s in suggestions
        ],
    }
    ports_path.write_text(json.dumps(port_list, indent=2) + "\n", encoding="utf-8")

    return len(suggestions), conf_path, ports_path
