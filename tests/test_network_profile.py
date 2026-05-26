from pathlib import Path

from fw_audit.network.outbound import build_outbound_service_uses, analyze_outbound_whitelist
from fw_audit.network.profile_audit import audit_network_profile
from fw_audit.classify.engine import ClassificationEngine, load_policy
from fw_audit.models import Connection, Host
from fw_audit.parsers.network_profile import parse_ipconfig_windows, parse_linux_network_bundle

FIXTURES = Path(__file__).parent.parent / "examples" / "home-lab"


def test_parse_linux_network_profile():
    text = (FIXTURES / "imports/pc01/network-linux.txt").read_text()
    prof = parse_linux_network_bundle(text, "H001")
    assert prof.default_gateway == "192.168.1.1"
    assert "192.168.1.1" in prof.dns_servers
    kinds = {i.kind for i in prof.interfaces}
    assert "wifi" in kinds
    assert "ethernet" in kinds


def test_untrusted_dns_finding():
    policy = load_policy()
    policy["outbound_whitelist"] = {
        "trusted_dns": ["192.168.1.1"],
        "trusted_gateways": ["192.168.1.1"],
        "client_interface_policy": {"wifi_allowed": False, "bluetooth_allowed": True},
    }
    text = (FIXTURES / "imports/pc01/network-linux.txt").read_text()
    prof = parse_linux_network_bundle(text, "H001")
    host = Host(id="H001", hostname="pc01", zone="internal", role="workstation")
    findings = audit_network_profile(prof, host, policy)
    assert any(f.code == "WIFI_INTERFACE_UP" for f in findings)


def test_outbound_whitelist_enforce():
    policy = load_policy(FIXTURES / "policy-outbound-whitelist.yaml")
    engine = ClassificationEngine(policy)
    conns = [
        Connection(
            host_id="H001",
            protocol="tcp",
            local_address="192.168.1.10",
            local_port=50000,
            remote_address="8.8.8.8",
            remote_port=443,
            state="ESTABLISHED",
            process_name="curl",
        )
    ]
    uses = build_outbound_service_uses(conns, "H001", engine, policy)
    assert len(uses) == 1
    assert uses[0].approved is True
    conns[0].remote_port = 6667
    uses2 = build_outbound_service_uses(conns, "H001", engine, policy)
    findings = analyze_outbound_whitelist(uses2, policy)
    assert any(f.code == "UNAPPROVED_OUTBOUND" for f in findings)
