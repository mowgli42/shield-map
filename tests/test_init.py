from pathlib import Path

from fw_audit.init.profile import HostIntent, build_listeners_from_intent, load_intent
from fw_audit.init.pipeline import run_init

EXAMPLES = Path(__file__).parent.parent / "examples" / "home-lab"


def test_build_client_minimal():
    intent = HostIntent(
        hostname="pc",
        host_type="client",
        os_family="windows",
        allow_rdp=False,
    )
    listeners, policy = build_listeners_from_intent(intent)
    inbound = [ln for ln in listeners if ln.state != "planned-outbound"]
    assert len(inbound) == 0
    assert policy.get("init_baseline") is True


def test_build_server_fileshare_ssh():
    intent = HostIntent(
        hostname="nas",
        host_type="server",
        os_family="linux",
        mgmt_cidr="10.0.0.0/24",
        services=["ssh", "fileshare"],
        web_mode="https-only",
    )
    listeners, _ = build_listeners_from_intent(intent)
    ports = {(ln.protocol, ln.port) for ln in listeners}
    assert ("tcp", 22) in ports
    assert ("tcp", 445) in ports
    ssh = next(ln for ln in listeners if ln.port == 22)
    assert ssh.allowed_sources == ["10.0.0.0/24"]
    assert ("tcp", 80) not in ports


def test_init_pipeline_non_interactive(tmp_path):
    answers = EXAMPLES / "init-answers-server.yaml"
    intent = load_intent(answers)
    ctx = run_init(intent, tmp_path, platforms=["nftables"])
    assert (tmp_path / "init-profile.yaml").is_file()
    assert (tmp_path / "audit-report.xml").is_file()
    rules = (tmp_path / "nas01" / "rules-nftables.conf").read_text()
    assert "policy drop" in rules
    assert "ip saddr 192.168.1.0/24" in rules
    assert "dport 445" in rules
    assert "dport 443" in rules
    assert "dport 80" not in rules
