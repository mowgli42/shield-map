from pathlib import Path

from fw_audit.graph.cross_zone import cross_zone_findings
from fw_audit.graph.flows import build_flows
from fw_audit.graph.ipmap import build_ip_to_host, resolve_host
from fw_audit.models import Classification, Flow, Host
from fw_audit.pipeline import run_audit
from fw_audit.policy.loader import load_hosts, load_zone_policy
from fw_audit.parsers.connections import parse_connections_windows

EXAMPLES = Path(__file__).parent.parent / "examples" / "dmz-lab"


def test_parse_established_windows():
    text = (EXAMPLES / "imports/pc01/netstat.txt").read_text()
    conns = parse_connections_windows(text, "H001")
    assert len(conns) >= 2
    ports = {(c.remote_address, c.remote_port) for c in conns}
    assert ("10.0.0.5", 443) in ports


def test_ip_map_resolve():
    hosts = load_hosts(EXAMPLES / "hosts.yaml")
    ip_map = build_ip_to_host(hosts)
    assert resolve_host("192.168.1.10", ip_map).hostname == "pc01"
    assert resolve_host("10.0.0.5", ip_map).hostname == "web01"


def test_dmz_lab_multi_host_audit(tmp_path):
    out = tmp_path / "out"
    ctx = run_audit(
        EXAMPLES / "imports",
        out,
        hosts_file=EXAMPLES / "hosts.yaml",
        platforms=["nftables", "cisco"],
    )
    assert len(ctx.hosts) == 3
    session_flows = [f for f in ctx.flows if f.flow_kind == "session"]
    assert len(session_flows) >= 2
    assert (out / "network-dataflow.dot").is_file()
    assert list(out.rglob("rules-cisco-ios.acl"))
    zones = {(f.client_zone, f.server_zone) for f in session_flows if f.client_host_id}
    assert ("internal", "dmz") in zones or any(
        f.client_zone == "internal" and f.server_zone == "dmz" for f in session_flows
    )


def test_cross_zone_blocked_pair():
    hosts = {
        "H001": Host(id="H001", hostname="a", zone="public"),
        "H002": Host(id="H002", hostname="b", zone="internal"),
    }
    flows = [
        Flow(
            id="S001",
            server_host_id="H002",
            server_address="10.0.0.1",
            server_zone="internal",
            protocol="tcp",
            port=22,
            classification=Classification.RISKY,
            client_host_id="H001",
            client_zone="public",
            flow_kind="session",
        )
    ]
    policy = {"allowed_zone_pairs": [{"from": "internal", "to": "dmz"}]}
    findings = cross_zone_findings(flows, hosts, policy)
    assert any(f.code == "CROSS_ZONE_UNRESTRICTED" for f in findings)
