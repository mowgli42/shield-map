import csv
import json
from pathlib import Path

import yaml

from fw_audit.models import (
    AuditContext,
    Classification,
    Host,
    Listener,
)
from fw_audit.pipeline import run_audit
from fw_audit.report.ports_protocols import (
    build_ports_protocols_entries,
    write_ports_protocols,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_build_entries_fields():
    ctx = AuditContext(
        hosts=[Host(id="H001", hostname="web01", zone="dmz", role="web")],
        listeners=[
            Listener(
                host_id="H001",
                protocol="tcp",
                port=443,
                bind_address="0.0.0.0",
                classification=Classification.PREFERRED,
                service_name="https",
                allowed_sources=["10.0.0.0/8"],
                state="listening",
            ),
            Listener(
                host_id="H001",
                protocol="tcp",
                port=22,
                bind_address="10.0.0.5",
                classification=Classification.PREFERRED,
                service_name="ssh",
                allowed_sources=["10.0.0.0/24"],
                state="planned",
            ),
        ],
    )
    entries = build_ports_protocols_entries(ctx)
    assert len(entries) == 2
    https = entries[0]
    assert https["host"] == "web01"
    assert https["zone"] == "dmz"
    assert https["role"] == "web"
    assert https["protocol"] == "tcp"
    assert https["port"] == 443
    assert https["service"] == "https"
    assert https["classification"] == "preferred"
    assert https["bind_address"] == "0.0.0.0"
    assert https["allowed_sources"] == ["10.0.0.0/8"]
    assert https["observed_vs_planned"] == "observed"
    assert "NIST:AC-4" in https["control_tags"]
    assert "CIS:9.2" in https["control_tags"]
    assert entries[1]["observed_vs_planned"] == "planned"


def test_write_json_yaml_csv(tmp_path):
    ctx = AuditContext(
        hosts=[Host(id="H001", hostname="pc01", zone="internal", role="workstation")],
        listeners=[
            Listener(
                host_id="H001",
                protocol="tcp",
                port=23,
                bind_address="0.0.0.0",
                classification=Classification.UNSAFE,
                service_name="telnet",
            )
        ],
        policy_version="1.0",
        operator="test",
    )
    paths = write_ports_protocols(ctx, tmp_path)
    assert paths["json"].is_file()
    assert paths["yaml"].is_file()
    assert paths["csv"].is_file()

    doc = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert doc["version"] == "1.0"
    assert doc["policyVersion"] == "1.0"
    assert len(doc["entries"]) == 1
    assert "CIS:12.4" in doc["entries"][0]["control_tags"]

    ydoc = yaml.safe_load(paths["yaml"].read_text(encoding="utf-8"))
    assert ydoc["entries"][0]["port"] == 23

    with paths["csv"].open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["service"] == "telnet"
    assert "CIS:12.4" in rows[0]["control_tags"]


def test_pipeline_emits_matrix(tmp_path):
    out = tmp_path / "out"
    ctx = run_audit(
        FIXTURES / "netstat-windows.txt",
        out,
        platforms=[],
    )
    assert len(ctx.listeners) >= 4
    matrix = out / "ports-protocols.json"
    assert matrix.is_file()
    assert (out / "ports-protocols.yaml").is_file()
    assert (out / "ports-protocols.csv").is_file()
    # XML path unchanged
    assert (out / "audit-report.xml").is_file()

    doc = json.loads(matrix.read_text(encoding="utf-8"))
    ports = {e["port"] for e in doc["entries"]}
    assert 443 in ports
    assert 23 in ports
    unsafe = [e for e in doc["entries"] if e["classification"] == "unsafe"]
    assert unsafe
    assert all(e["observed_vs_planned"] == "observed" for e in doc["entries"])
