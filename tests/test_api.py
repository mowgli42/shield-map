"""Tests for the stable fw_audit library API (SnarkSentinel contract)."""

from pathlib import Path

from fw_audit import (
    __version__,
    analyze,
    diff,
    generate_local_only,
    load_audit_xml,
)
from fw_audit.api import AnalyzeResult
from fw_audit.models import Classification, Listener
from fw_audit.pipeline import run_audit

FIXTURES = Path(__file__).parent / "fixtures"


def test_public_exports():
    assert __version__
    assert callable(analyze)
    assert callable(diff)
    assert callable(generate_local_only)
    assert callable(load_audit_xml)


def test_analyze_listeners(tmp_path):
    result = analyze(FIXTURES / "ss-linux.txt")
    assert isinstance(result, AnalyzeResult)
    assert len(result.listeners) >= 3
    ports = {(ln.protocol, ln.port) for ln in result.listeners}
    assert ("tcp", 22) in ports
    assert ("tcp", 80) in ports
    payload = result.to_dict()
    assert "summary" in payload
    assert "listeners" in payload
    assert payload["connection_count"] >= 0
    # analyze must not require or create an output directory
    assert list(tmp_path.iterdir()) == []


def test_diff_detects_added_listener(tmp_path):
    baseline_out = tmp_path / "baseline"
    run_audit(FIXTURES / "ss-linux.txt", baseline_out, platforms=[], export_dot=False)
    baseline = load_audit_xml(baseline_out / "audit-report.xml")

    current = analyze(FIXTURES / "ss-linux.txt")
    # Simulate drift: new unsafe-ish bind
    current.listeners.append(
        Listener(
            host_id=current.listeners[0].host_id,
            protocol="tcp",
            port=2375,
            bind_address="0.0.0.0",
            classification=Classification.UNSAFE,
            service_name="docker-api",
        )
    )

    report = diff(baseline, current)
    assert report.has_drift
    added = [c for c in report.changes if c.kind == "added" and c.subject == "listener"]
    assert any("2375" in c.key for c in added)
    assert report.to_dict()["has_drift"] is True


def test_diff_no_drift_same_export(tmp_path):
    out = tmp_path / "out"
    run_audit(FIXTURES / "ss-linux.txt", out, platforms=[], export_dot=False)
    baseline = out / "audit-report.xml"
    current = analyze(FIXTURES / "ss-linux.txt")
    report = diff(baseline, current)
    listener_changes = [c for c in report.changes if c.subject == "listener"]
    assert listener_changes == []


def test_generate_local_only_profile(tmp_path):
    profile = generate_local_only(
        tmp_path,
        hostname="agent01",
        os_family="linux",
        guardian_socket="/run/guardian.sock",
    )
    assert profile.profile_path.is_file()
    assert profile.audit_xml_path.is_file()
    text = profile.profile_path.read_text()
    assert "local-only" in text
    assert "/run/guardian.sock" in text
    assert text.count("remote_inbound_denied") >= 1

    nft = Path(profile.rulesets[0].path).read_text()
    assert "policy drop" in nft
    assert "iif lo accept" in nft
    assert "guardian" in nft.lower()
    # No non-loopback TCP allow ports for remote inbound
    assert "dport" not in nft

    payload = profile.to_dict()
    assert payload["loopback_allowed"] is True
    assert payload["remote_inbound_denied"] is True
