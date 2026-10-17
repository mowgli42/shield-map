"""Tests for shield-map / shield-up / shield-audit entry points."""

from pathlib import Path

from typer.testing import CliRunner

from fw_audit.entrypoints import shield_map_app
from fw_audit.pipeline import run_audit

FIXTURE_SS = Path(__file__).parent / "fixtures" / "ss-linux.txt"
runner = CliRunner()


def test_shield_map_from_input(tmp_path):
    result = runner.invoke(
        shield_map_app,
        ["--input", str(FIXTURE_SS), "-o", str(tmp_path / "out"), "--platform", "nftables"],
    )
    assert result.exit_code == 0, result.output
    out = tmp_path / "out"
    assert (out / "audit-report.xml").is_file()
    assert list(out.rglob("rules-nftables.conf"))
    assert list(out.rglob("jail.d/shield-map.conf"))


def test_shield_audit_no_drift(tmp_path):
    import sys

    from fw_audit.entrypoints import shield_audit

    baseline_dir = tmp_path / "baseline"
    run_audit(FIXTURE_SS, baseline_dir, platforms=[], export_dot=False)
    baseline = baseline_dir / "audit-report.xml"
    current = tmp_path / "current"

    old = sys.argv
    try:
        sys.argv = [
            "shield-audit",
            "--baseline",
            str(baseline),
            "--output-dir",
            str(current),
            "--input",
            str(FIXTURE_SS),
        ]
        try:
            shield_audit()
            raised = None
        except SystemExit as exc:
            raised = exc.code
    finally:
        sys.argv = old

    assert raised in (None, 0)
    assert (current / "drift-summary.txt").is_file()
    assert (current / "audit-report.xml").is_file()


def test_root_scripts_exist_and_executable():
    root = Path(__file__).resolve().parents[1]
    for name in ("shield-map", "shield-up", "shield-audit", "_shield_lib.sh"):
        path = root / name
        assert path.is_file(), name
        if name != "_shield_lib.sh":
            assert path.stat().st_mode & 0o111, f"{name} should be executable"
