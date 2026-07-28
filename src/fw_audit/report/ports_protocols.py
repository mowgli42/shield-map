"""Machine-parseable ports-and-protocols matrix export (JSON/YAML/CSV)."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from fw_audit import __version__
from fw_audit.models import AuditContext, Classification, Listener


def _observed_vs_planned(listener: Listener) -> str:
    if listener.state.startswith("planned"):
        return "planned"
    return "observed"


def _control_tags(classification: Classification) -> list[str]:
    """Map listener classification to CIS / NIST control tags for evidence consumers."""
    tags = ["NIST:AC-4", "NIST:SC-7"]
    if classification == Classification.UNSAFE:
        tags.extend(["CIS:12.4", "NIST:SC-7(5)"])
    elif classification == Classification.RISKY:
        tags.extend(["CIS:9.2", "CIS:9.4"])
    elif classification == Classification.PREFERRED:
        tags.extend(["CIS:9.2", "CIS:9.4"])
    else:
        tags.append("CIS:9.2")
    return tags


def build_ports_protocols_entries(ctx: AuditContext) -> list[dict[str, Any]]:
    hosts_by_id = {h.id: h for h in ctx.hosts}
    entries: list[dict[str, Any]] = []
    for ln in ctx.listeners:
        host = hosts_by_id.get(ln.host_id)
        entries.append(
            {
                "host": host.hostname if host else ln.host_id,
                "host_id": ln.host_id,
                "zone": host.zone if host else "unknown",
                "role": host.role if host else "unknown",
                "protocol": ln.protocol,
                "port": ln.port,
                "service": ln.service_name or f"port-{ln.port}",
                "classification": ln.classification.value,
                "bind_address": ln.bind_address,
                "allowed_sources": list(ln.allowed_sources),
                "observed_vs_planned": _observed_vs_planned(ln),
                "control_tags": _control_tags(ln.classification),
            }
        )
    return entries


def build_ports_protocols_document(ctx: AuditContext) -> dict[str, Any]:
    return {
        "version": "1.0",
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "toolVersion": __version__,
        "policyVersion": ctx.policy_version,
        "operator": ctx.operator,
        "entries": build_ports_protocols_entries(ctx),
    }


def write_ports_protocols(ctx: AuditContext, output_dir: Path) -> dict[str, Path]:
    """Write ports-protocols.json plus YAML/CSV sidecars. Returns written paths."""
    output_dir.mkdir(parents=True, exist_ok=True)
    doc = build_ports_protocols_document(ctx)
    paths: dict[str, Path] = {}

    json_path = output_dir / "ports-protocols.json"
    json_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    paths["json"] = json_path

    yaml_path = output_dir / "ports-protocols.yaml"
    with yaml_path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False, allow_unicode=True)
    paths["yaml"] = yaml_path

    csv_path = output_dir / "ports-protocols.csv"
    fieldnames = [
        "host",
        "host_id",
        "zone",
        "role",
        "protocol",
        "port",
        "service",
        "classification",
        "bind_address",
        "allowed_sources",
        "observed_vs_planned",
        "control_tags",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for entry in doc["entries"]:
            row = dict(entry)
            row["allowed_sources"] = ";".join(entry["allowed_sources"])
            row["control_tags"] = ";".join(entry["control_tags"])
            writer.writerow(row)
    paths["csv"] = csv_path

    return paths
