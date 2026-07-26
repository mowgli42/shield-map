"""Compare two NetworkAuditReport XML snapshots for configuration drift."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

RISKY_UNSAFE = frozenset({"risky", "unsafe"})

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass(frozen=True)
class SnapshotListener:
    host_ref: str
    protocol: str
    port: int
    bind_address: str
    classification: str
    service: str = ""

    @property
    def key(self) -> tuple[str, str, int, str]:
        return (self.host_ref, self.protocol.lower(), self.port, self.bind_address)


@dataclass(frozen=True)
class SnapshotCrossZoneFlow:
    client_zone: str
    server_zone: str
    protocol: str
    port: int
    client_host: str = ""
    server_host: str = ""
    classification: str = "unknown"
    service: str = ""

    @property
    def key(self) -> tuple[str, str, str, int, str, str]:
        return (
            self.client_zone,
            self.server_zone,
            self.protocol.lower(),
            self.port,
            self.client_host,
            self.server_host,
        )


@dataclass
class AuditSnapshot:
    path: str
    generated_at: str = ""
    tool_version: str = ""
    listeners: list[SnapshotListener] = field(default_factory=list)
    cross_zone_flows: list[SnapshotCrossZoneFlow] = field(default_factory=list)


@dataclass
class DriftFinding:
    code: str
    severity: str
    message: str
    host_ref: str = ""
    protocol: Optional[str] = None
    port: Optional[int] = None
    baseline: Optional[str] = None
    current: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class DiffResult:
    baseline: str
    current: str
    findings: list[DriftFinding] = field(default_factory=list)

    @property
    def drift_detected(self) -> bool:
        return bool(self.findings)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.code] = counts.get(finding.code, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline,
            "current": self.current,
            "drift_detected": self.drift_detected,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_text(self) -> str:
        lines = [
            f"Diff: {self.baseline} → {self.current}",
            f"Drift detected: {'yes' if self.drift_detected else 'no'}",
            f"Findings: {len(self.findings)}",
        ]
        if self.findings:
            lines.append("")
            for finding in self.findings:
                loc = ""
                if finding.host_ref:
                    loc = f" host={finding.host_ref}"
                if finding.protocol and finding.port is not None:
                    loc += f" {finding.protocol}/{finding.port}"
                lines.append(f"  [{finding.severity}] {finding.code}{loc}: {finding.message}")
        return "\n".join(lines)


def _local(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _first_child(parent: ET.Element, name: str) -> Optional[ET.Element]:
    for child in list(parent):
        if _local(child.tag) == name:
            return child
    return None


def _children(parent: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(parent) if _local(child.tag) == name]


def _attr(el: ET.Element, *names: str, default: str = "") -> str:
    for name in names:
        if name in el.attrib:
            return el.attrib[name]
    return default


def _listener_service(el: ET.Element) -> str:
    service = _first_child(el, "Service")
    if service is not None and service.text:
        return service.text.strip()
    return ""


def _parse_listener(el: ET.Element) -> Optional[SnapshotListener]:
    port_raw = _attr(el, "port", default="")
    if not port_raw:
        return None
    port = int(port_raw)
    if port <= 0:
        return None
    return SnapshotListener(
        host_ref=_attr(el, "hostRef", "host_ref"),
        protocol=_attr(el, "protocol", default="tcp"),
        port=port,
        bind_address=_attr(el, "bindAddress", "bind_address", default="0.0.0.0"),
        classification=_attr(el, "classification", default="unknown"),
        service=_listener_service(el),
    )


def _parse_cross_zone_flow(flow_el: ET.Element) -> Optional[SnapshotCrossZoneFlow]:
    client = _first_child(flow_el, "Client")
    server = _first_child(flow_el, "Server")
    service = _first_child(flow_el, "Service")
    if client is None or server is None or service is None:
        return None

    client_zone = _attr(client, "zone", default="unknown")
    server_zone = _attr(server, "zone", default="unknown")
    if not client_zone or not server_zone or client_zone == server_zone:
        return None

    flow_kind = _attr(flow_el, "flowKind", "flow_kind", default="")
    # Listener-derived flows often use client_zone=unknown for public binds; skip those.
    if flow_kind == "listener" and client_zone == "unknown":
        return None

    port_raw = _attr(service, "port", default="")
    if not port_raw:
        return None
    port = int(port_raw)
    if port <= 0:
        return None

    return SnapshotCrossZoneFlow(
        client_zone=client_zone,
        server_zone=server_zone,
        protocol=_attr(service, "protocol", default="tcp"),
        port=port,
        client_host=_attr(client, "hostRef", "host_ref"),
        server_host=_attr(server, "hostRef", "host_ref"),
        classification=_attr(flow_el, "classification", default="unknown"),
        service=_attr(service, "name", default=""),
    )


def load_snapshot(path: Path) -> AuditSnapshot:
    """Load listeners and cross-zone flows from an audit-report.xml file."""
    tree = ET.parse(path)
    root = tree.getroot()
    if _local(root.tag) != "NetworkAuditReport":
        raise ValueError(f"Not a NetworkAuditReport: {path}")

    observed = _first_child(root, "ObservedListeners")
    listeners: list[SnapshotListener] = []
    if observed is not None:
        for el in _children(observed, "Listener"):
            parsed = _parse_listener(el)
            if parsed is not None:
                listeners.append(parsed)
    else:
        # Fallback for fixtures missing the wrapper element.
        for el in root.iter():
            if _local(el.tag) == "Listener":
                parsed = _parse_listener(el)
                if parsed is not None:
                    listeners.append(parsed)

    flows_el = _first_child(root, "Flows")
    cross_zone: list[SnapshotCrossZoneFlow] = []
    flow_nodes = _children(flows_el, "Flow") if flows_el is not None else []
    if not flow_nodes:
        flow_nodes = [el for el in root.iter() if _local(el.tag) == "Flow"]
    for flow_el in flow_nodes:
        parsed = _parse_cross_zone_flow(flow_el)
        if parsed is not None:
            cross_zone.append(parsed)

    return AuditSnapshot(
        path=str(path),
        generated_at=_attr(root, "generatedAt", "generated_at"),
        tool_version=_attr(root, "toolVersion", "tool_version"),
        listeners=listeners,
        cross_zone_flows=cross_zone,
    )


def compare_snapshots(baseline: AuditSnapshot, current: AuditSnapshot) -> DiffResult:
    """Emit drift findings for unsafe/risky listener changes, classification changes, and cross-zone flows."""
    findings: list[DriftFinding] = []

    base_listeners = {ln.key: ln for ln in baseline.listeners}
    curr_listeners = {ln.key: ln for ln in current.listeners}

    for key, ln in curr_listeners.items():
        if key not in base_listeners and ln.classification in RISKY_UNSAFE:
            severity = "critical" if ln.classification == "unsafe" else "high"
            findings.append(
                DriftFinding(
                    code="LISTENER_ADDED",
                    severity=severity,
                    message=(
                        f"New {ln.classification} listener {ln.protocol}/{ln.port} "
                        f"on {ln.bind_address}"
                        + (f" ({ln.service})" if ln.service else "")
                    ),
                    host_ref=ln.host_ref,
                    protocol=ln.protocol,
                    port=ln.port,
                    current=ln.classification,
                )
            )

    for key, ln in base_listeners.items():
        if key not in curr_listeners and ln.classification in RISKY_UNSAFE:
            findings.append(
                DriftFinding(
                    code="LISTENER_REMOVED",
                    severity="medium",
                    message=(
                        f"Removed {ln.classification} listener {ln.protocol}/{ln.port} "
                        f"on {ln.bind_address}"
                        + (f" ({ln.service})" if ln.service else "")
                    ),
                    host_ref=ln.host_ref,
                    protocol=ln.protocol,
                    port=ln.port,
                    baseline=ln.classification,
                )
            )

    for key, base_ln in base_listeners.items():
        curr_ln = curr_listeners.get(key)
        if curr_ln is None:
            continue
        if base_ln.classification != curr_ln.classification:
            severity = _classification_change_severity(
                base_ln.classification, curr_ln.classification
            )
            findings.append(
                DriftFinding(
                    code="CLASSIFICATION_CHANGED",
                    severity=severity,
                    message=(
                        f"Classification changed {base_ln.classification} → "
                        f"{curr_ln.classification} for {curr_ln.protocol}/{curr_ln.port}"
                    ),
                    host_ref=curr_ln.host_ref,
                    protocol=curr_ln.protocol,
                    port=curr_ln.port,
                    baseline=base_ln.classification,
                    current=curr_ln.classification,
                )
            )

    base_flows = {f.key: f for f in baseline.cross_zone_flows}
    curr_flows = {f.key: f for f in current.cross_zone_flows}

    for key, flow in curr_flows.items():
        if key not in base_flows:
            findings.append(
                DriftFinding(
                    code="CROSS_ZONE_ADDED",
                    severity="high",
                    message=(
                        f"New cross-zone flow {flow.client_zone}→{flow.server_zone} "
                        f"{flow.protocol}/{flow.port}"
                        + (f" ({flow.service})" if flow.service else "")
                    ),
                    host_ref=flow.server_host,
                    protocol=flow.protocol,
                    port=flow.port,
                    current=f"{flow.client_zone}->{flow.server_zone}",
                )
            )

    for key, flow in base_flows.items():
        if key not in curr_flows:
            findings.append(
                DriftFinding(
                    code="CROSS_ZONE_REMOVED",
                    severity="info",
                    message=(
                        f"Removed cross-zone flow {flow.client_zone}→{flow.server_zone} "
                        f"{flow.protocol}/{flow.port}"
                        + (f" ({flow.service})" if flow.service else "")
                    ),
                    host_ref=flow.server_host,
                    protocol=flow.protocol,
                    port=flow.port,
                    baseline=f"{flow.client_zone}->{flow.server_zone}",
                )
            )

    findings.sort(
        key=lambda f: (
            _SEVERITY_ORDER.index(f.severity) if f.severity in _SEVERITY_ORDER else 99,
            f.code,
            f.host_ref,
            f.port or 0,
        )
    )
    return DiffResult(baseline=baseline.path, current=current.path, findings=findings)


def _classification_change_severity(baseline: str, current: str) -> str:
    rank = {"preferred": 0, "unknown": 1, "risky": 2, "unsafe": 3}
    b = rank.get(baseline, 1)
    c = rank.get(current, 1)
    if c > b:
        return "critical" if current == "unsafe" else "high"
    if c < b:
        return "low"
    return "medium"


def diff_paths(baseline: Path, current: Path) -> DiffResult:
    return compare_snapshots(load_snapshot(baseline), load_snapshot(current))
