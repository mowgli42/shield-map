"""Tests for fw-audit diff (configuration drift)."""

from pathlib import Path

from typer.testing import CliRunner

from fw_audit.cli import app
from fw_audit.diff.compare import (
    AuditSnapshot,
    SnapshotCrossZoneFlow,
    SnapshotListener,
    compare_snapshots,
    load_snapshot,
)

NS = "urn:fw-audit:network-audit:1"
runner = CliRunner()


def _write_report(
    path: Path,
    listeners: list[dict],
    flows: list[dict] | None = None,
) -> Path:
    flow_xml = ""
    for flow in flows or []:
        flow_xml += f"""
    <Flow id="{flow['id']}" classification="{flow.get('classification', 'preferred')}" flowKind="{flow.get('flow_kind', 'session')}">
      <Client hostRef="{flow.get('client_host', '')}" zone="{flow['client_zone']}" address="{flow.get('client_address', '')}"/>
      <Server hostRef="{flow.get('server_host', '')}" zone="{flow['server_zone']}" address="{flow.get('server_address', '')}"/>
      <Service protocol="{flow.get('protocol', 'tcp')}" port="{flow['port']}" name="{flow.get('service', '')}"/>
    </Flow>"""

    listener_xml = ""
    for ln in listeners:
        service = f"<Service>{ln['service']}</Service>" if ln.get("service") else ""
        listener_xml += f"""
    <Listener hostRef="{ln['host']}" protocol="{ln.get('protocol', 'tcp')}" port="{ln['port']}" bindAddress="{ln.get('bind', '0.0.0.0')}" classification="{ln['classification']}">{service}</Listener>"""

    path.write_text(
        f"""<?xml version="1.0" encoding="utf-8"?>
<NetworkAuditReport xmlns="{NS}" version="1.0" generatedAt="2026-07-26T00:00:00Z" toolVersion="0.1.0">
  <Metadata>
    <PolicyVersion>1.0</PolicyVersion>
    <Operator>test</Operator>
  </Metadata>
  <ComplianceMapping>
    <Framework name="CIS Controls" version="8.1"/>
  </ComplianceMapping>
  <ExecutiveSummary>
    <Count classification="preferred">0</Count>
  </ExecutiveSummary>
  <Inventory>
    <Host id="H001" hostname="web01" zone="dmz" role="server"/>
  </Inventory>
  <ObservedListeners>{listener_xml}
  </ObservedListeners>
  <Flows>{flow_xml}
  </Flows>
  <Findings/>
</NetworkAuditReport>
""",
        encoding="utf-8",
    )
    return path


def test_load_snapshot_listeners_and_cross_zone(tmp_path):
    path = _write_report(
        tmp_path / "audit-report.xml",
        listeners=[
            {"host": "H001", "port": 443, "classification": "preferred", "service": "https"},
            {"host": "H001", "port": 23, "classification": "unsafe", "service": "telnet"},
        ],
        flows=[
            {
                "id": "S001",
                "client_zone": "internal",
                "server_zone": "dmz",
                "client_host": "H002",
                "server_host": "H001",
                "port": 443,
                "service": "https",
            },
            {
                "id": "L001",
                "client_zone": "unknown",
                "server_zone": "dmz",
                "server_host": "H001",
                "port": 443,
                "flow_kind": "listener",
            },
        ],
    )
    snap = load_snapshot(path)
    assert len(snap.listeners) == 2
    assert {ln.port for ln in snap.listeners} == {443, 23}
    assert len(snap.cross_zone_flows) == 1
    assert snap.cross_zone_flows[0].client_zone == "internal"


def test_compare_detects_listener_and_classification_and_cross_zone_drift():
    baseline = AuditSnapshot(
        path="baseline.xml",
        listeners=[
            SnapshotListener("H001", "tcp", 445, "0.0.0.0", "risky", "smb"),
            SnapshotListener("H001", "tcp", 443, "0.0.0.0", "preferred", "https"),
        ],
        cross_zone_flows=[
            SnapshotCrossZoneFlow("internal", "dmz", "tcp", 443, "H002", "H001", service="https"),
        ],
    )
    current = AuditSnapshot(
        path="current.xml",
        listeners=[
            SnapshotListener("H001", "tcp", 23, "0.0.0.0", "unsafe", "telnet"),
            SnapshotListener("H001", "tcp", 443, "0.0.0.0", "risky", "https"),
        ],
        cross_zone_flows=[
            SnapshotCrossZoneFlow("public", "internal", "tcp", 22, "H003", "H001", service="ssh"),
        ],
    )
    result = compare_snapshots(baseline, current)
    codes = {f.code for f in result.findings}
    assert "LISTENER_ADDED" in codes
    assert "LISTENER_REMOVED" in codes
    assert "CLASSIFICATION_CHANGED" in codes
    assert "CROSS_ZONE_ADDED" in codes
    assert "CROSS_ZONE_REMOVED" in codes
    assert result.drift_detected

    added = next(f for f in result.findings if f.code == "LISTENER_ADDED")
    assert added.port == 23
    assert added.severity == "critical"

    changed = next(f for f in result.findings if f.code == "CLASSIFICATION_CHANGED")
    assert changed.baseline == "preferred"
    assert changed.current == "risky"


def test_compare_identical_snapshots_no_drift():
    snap = AuditSnapshot(
        path="a.xml",
        listeners=[SnapshotListener("H001", "tcp", 80, "0.0.0.0", "risky")],
        cross_zone_flows=[
            SnapshotCrossZoneFlow("internal", "dmz", "tcp", 80, "H002", "H001"),
        ],
    )
    other = AuditSnapshot(
        path="b.xml",
        listeners=list(snap.listeners),
        cross_zone_flows=list(snap.cross_zone_flows),
    )
    result = compare_snapshots(snap, other)
    assert result.findings == []
    assert result.drift_detected is False


def test_cli_diff_json_and_exit_code(tmp_path):
    baseline = _write_report(
        tmp_path / "baseline.xml",
        listeners=[{"host": "H001", "port": 445, "classification": "risky"}],
    )
    current = _write_report(
        tmp_path / "current.xml",
        listeners=[
            {"host": "H001", "port": 445, "classification": "risky"},
            {"host": "H001", "port": 23, "classification": "unsafe"},
        ],
    )
    result = runner.invoke(app, ["diff", str(baseline), str(current), "--format", "json"])
    assert result.exit_code == 1
    assert '"LISTENER_ADDED"' in result.stdout
    assert '"drift_detected": true' in result.stdout

    clean = runner.invoke(
        app,
        ["diff", str(baseline), str(baseline), "--format", "text", "--no-exit-code"],
    )
    assert clean.exit_code == 0
    assert "Drift detected: no" in clean.stdout


def test_cli_diff_missing_file(tmp_path):
    missing = tmp_path / "missing.xml"
    other = _write_report(tmp_path / "ok.xml", listeners=[])
    result = runner.invoke(app, ["diff", str(missing), str(other)])
    assert result.exit_code == 2
    assert "Baseline not found" in result.output
