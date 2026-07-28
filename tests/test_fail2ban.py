"""Tests for Fail2ban jail.d generator."""

from pathlib import Path

from fw_audit.generators.fail2ban import generate_fail2ban
from fw_audit.models import Classification, Host, Listener
from fw_audit.pipeline import run_audit

FIXTURES = Path(__file__).parent / "fixtures"


def test_generate_fail2ban_enabled_for_stock_filters(tmp_path):
    host = Host(id="H001", hostname="web01", zone="dmz", os_family="linux")
    listeners = [
        Listener(
            host_id="H001",
            protocol="tcp",
            port=22,
            bind_address="0.0.0.0",
            classification=Classification.PREFERRED,
            service_name="ssh",
        ),
        Listener(
            host_id="H001",
            protocol="tcp",
            port=443,
            bind_address="0.0.0.0",
            classification=Classification.PREFERRED,
            service_name="https",
        ),
        Listener(
            host_id="H001",
            protocol="tcp",
            port=3389,
            bind_address="0.0.0.0",
            classification=Classification.RISKY,
            service_name="rdp",
        ),
    ]
    policy = {"approved_risky": [{"proto": "tcp", "port": 3389}]}
    out = tmp_path / "jail.d" / "fw-audit.conf"
    count = generate_fail2ban(host, listeners, policy, out)

    assert count == 3
    text = out.read_text()
    assert "banaction = nftables-multiport" in text
    assert "[fw-audit-ssh-22]" in text
    assert "filter = sshd" in text
    assert "enabled = true" in text
    assert "[fw-audit-rdp-3389]" in text
    assert "enabled = false" in text  # no stock filter for rdp
    assert "No stock Fail2ban filter" in text


def test_generate_fail2ban_skips_unapproved_risky(tmp_path):
    host = Host(id="H001", hostname="pc01", zone="internal")
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
    out = tmp_path / "fw-audit.conf"
    count = generate_fail2ban(host, listeners, {"approved_risky": []}, out)
    assert count == 0
    assert "No preferred/risky listeners" in out.read_text()


def test_pipeline_emits_fail2ban_with_nftables(tmp_path):
    out = tmp_path / "out"
    ctx = run_audit(
        FIXTURES / "netstat-windows.txt",
        out,
        platforms=["nftables"],
    )
    jails = list(out.rglob("jail.d/fw-audit.conf"))
    assert jails, "expected Fail2ban drop-in next to nftables rules"
    text = jails[0].read_text()
    assert "nftables-multiport" in text
    # Fixture includes unsafe telnet — must not receive a jail (policy denies it).
    assert "telnet" not in text.lower()
    assert "fw-audit-https-443" in text or "filter = nginx-http-auth" in text
    assert any(a.format == "jail.d" for a in ctx.rulesets)


def test_pipeline_fail2ban_only_platform(tmp_path):
    out = tmp_path / "out"
    run_audit(
        FIXTURES / "netstat-windows.txt",
        out,
        platforms=["fail2ban"],
    )
    assert list(out.rglob("jail.d/fw-audit.conf"))
    assert not list(out.rglob("rules-nftables.conf"))
