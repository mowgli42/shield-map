import json
from pathlib import Path

from fw_audit.classify.engine import ClassificationEngine, load_policy
from fw_audit.generators.opencanary import (
    generate_opencanary,
    suggest_canary_ports,
)
from fw_audit.models import Classification, Host, Listener
from fw_audit.pipeline import run_audit

FIXTURES = Path(__file__).parent / "fixtures"


def test_suggest_excludes_in_use_and_role_required():
    policy = load_policy()
    host = Host(id="H001", hostname="web01", zone="dmz", role="web")
    listeners = [
        Listener(
            host_id="H001",
            protocol="tcp",
            port=443,
            bind_address="0.0.0.0",
            classification=Classification.PREFERRED,
            service_name="https",
        ),
    ]
    suggestions = suggest_canary_ports(host, listeners, policy)
    ports = {(s["proto"], s["port"]) for s in suggestions}

    assert ("tcp", 443) not in ports  # in use + role-required
    assert ("tcp", 80) not in ports  # role-required for web
    assert ("tcp", 23) in ports  # unused unsafe
    assert ("tcp", 21) in ports  # unused unsafe
    assert ("tcp", 6379) in ports  # unused unsafe
    assert ("tcp", 22) in ports  # unused preferred — not required for web role


def test_server_role_keeps_ssh_out_of_canaries():
    policy = load_policy()
    host = Host(id="H002", hostname="nas01", zone="internal", role="server")
    listeners = [
        Listener(
            host_id="H002",
            protocol="tcp",
            port=445,
            bind_address="0.0.0.0",
            classification=Classification.RISKY,
            service_name="smb",
        ),
    ]
    suggestions = suggest_canary_ports(host, listeners, policy)
    ports = {(s["proto"], s["port"]) for s in suggestions}

    assert ("tcp", 22) not in ports  # role-required for server
    assert ("tcp", 445) not in ports  # in use
    assert ("tcp", 23) in ports


def test_generate_opencanary_writes_conf_and_port_list(tmp_path):
    policy = load_policy()
    host = Host(id="H001", hostname="pc01", zone="internal", role="workstation")
    listeners = [
        Listener(
            host_id="H001",
            protocol="tcp",
            port=3389,
            bind_address="0.0.0.0",
            classification=Classification.RISKY,
            service_name="rdp",
        ),
    ]
    engine = ClassificationEngine(policy)
    engine.apply_to_listeners(listeners, {"H001": host})

    count, conf_path, ports_path = generate_opencanary(host, listeners, policy, tmp_path)
    assert count >= 1
    assert conf_path.is_file()
    assert ports_path.is_file()

    conf = json.loads(conf_path.read_text(encoding="utf-8"))
    assert conf["device.node_id"] == "fw-audit-pc01"
    assert conf.get("rdp.enabled") is not True  # in use
    assert conf.get("telnet.enabled") is True
    assert conf.get("telnet.port") == 23

    ports_doc = json.loads(ports_path.read_text(encoding="utf-8"))
    assert ports_doc["role"] == "workstation"
    assert any(p["port"] == 23 for p in ports_doc["ports"])
    assert not any(p["port"] == 3389 for p in ports_doc["ports"])


def test_pipeline_emits_opencanary_artifacts(tmp_path):
    out = tmp_path / "out"
    ctx = run_audit(
        FIXTURES / "ss-linux.txt",
        out,
        platforms=["nftables"],
    )
    opencanary = [a for a in ctx.rulesets if a.platform == "opencanary"]
    assert len(opencanary) == 2
    conf = list(out.rglob(".opencanary.conf"))
    ports = list(out.rglob("opencanary-ports.json"))
    assert conf
    assert ports
    data = json.loads(ports[0].read_text(encoding="utf-8"))
    # Fixture listens on 22, 80, 6379 — those must not be suggested.
    suggested = {(p["proto"], p["port"]) for p in data["ports"]}
    assert ("tcp", 22) not in suggested
    assert ("tcp", 80) not in suggested
    assert ("tcp", 6379) not in suggested
    assert ("tcp", 23) in suggested
