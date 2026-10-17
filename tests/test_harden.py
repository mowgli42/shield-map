"""Tests for Linux harden stages, distro detection, and script generation."""

from __future__ import annotations

from pathlib import Path

import pytest

from fw_audit.harden.distro import DistroFamily, HostDistro, detect_distro
from fw_audit.harden.pipeline import HardenOptions, run_harden
from fw_audit.harden.scripts import BACKUP_DNS, PRIMARY_DNS, write_harden_scripts
from fw_audit.harden.stages import STAGE_ORDER, StageId, parse_stages

FIXTURE_SS = Path(__file__).parent / "fixtures" / "ss-linux.txt"


def _write_os_release(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_detect_omarchy_as_arch(tmp_path):
    osr = _write_os_release(
        tmp_path / "os-release",
        'NAME="Omarchy"\nID=omarchy\nID_LIKE=arch\nPRETTY_NAME="Omarchy"\n',
    )
    d = detect_distro(osr)
    assert d.family == DistroFamily.ARCH
    assert d.is_omarchy is True
    assert d.package_manager == "pacman"
    assert d.supported


def test_detect_ubuntu(tmp_path):
    osr = _write_os_release(
        tmp_path / "os-release",
        'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 24.04"\n',
    )
    d = detect_distro(osr)
    assert d.family == DistroFamily.UBUNTU
    assert d.package_manager == "apt"


def test_detect_rhel(tmp_path):
    osr = _write_os_release(
        tmp_path / "os-release",
        'NAME="Rocky Linux"\nID=rocky\nID_LIKE="rhel centos fedora"\n',
    )
    d = detect_distro(osr)
    assert d.family == DistroFamily.REDHAT
    assert d.package_manager == "dnf"


def test_parse_stages_order_and_unknown():
    assert parse_stages(None) == list(STAGE_ORDER)
    assert parse_stages("cron,discover") == [StageId.DISCOVER, StageId.CRON]
    with pytest.raises(ValueError, match="Unknown stage"):
        parse_stages("firewall,nope")


def test_scripts_tailored_per_family(tmp_path):
    host_out = tmp_path / "host"
    host_out.mkdir()
    (host_out / "rules-nftables.conf").write_text("table inet x {}\n", encoding="utf-8")
    (host_out / "jail.d").mkdir()
    (host_out / "jail.d" / "shield-map.conf").write_text(
        "[sshd]\nenabled=true\n", encoding="utf-8"
    )
    (host_out / ".opencanary.conf").write_text("{}\n", encoding="utf-8")
    baseline = tmp_path / "audit-report.xml"
    baseline.write_text("<NetworkAuditReport/>\n", encoding="utf-8")

    cases = [
        (DistroFamily.ARCH, "pacman", "Arch Linux"),
        (DistroFamily.UBUNTU, "apt-get", "Ubuntu"),
        (DistroFamily.REDHAT, "dnf", "Rocky"),
    ]
    for family, needle, pretty in cases:
        distro = HostDistro(
            family=family,
            id=family.value,
            id_like=(),
            pretty_name=pretty,
            package_manager="x",
        )
        scripts = write_harden_scripts(
            tmp_path / f"scripts-{family.value}",
            distro,
            host_out=host_out,
            baseline_xml=baseline,
        )
        deps = scripts["install_deps"].read_text(encoding="utf-8")
        assert needle in deps
        dns = scripts["setup_dns"].read_text(encoding="utf-8")
        assert PRIMARY_DNS in dns
        assert BACKUP_DNS in dns
        cron = scripts["setup_cron"].read_text(encoding="utf-8")
        assert "shield-audit" in cron
        assert scripts["drift"].is_file()


def test_harden_scripts_only_from_fixture(tmp_path):
    opts = HardenOptions(
        output_dir=tmp_path / "out",
        input_path=FIXTURE_SS,
        apply=False,
        hostname="testhost",
        distro=HostDistro(
            family=DistroFamily.ARCH,
            id="omarchy",
            id_like=("arch",),
            pretty_name="Omarchy",
            package_manager="pacman",
            is_omarchy=True,
        ),
        install_opencanary=False,
        update_dns=False,
    )
    echoes: list[str] = []
    result = run_harden(
        opts,
        echo=echoes.append,
        confirm=lambda _p, d: d,
    )
    assert result.export_path is not None
    assert result.export_path.is_file()
    assert result.baseline_xml is not None and result.baseline_xml.is_file()
    assert (tmp_path / "out" / "harden-scripts" / "02-apply-firewall.sh").is_file()
    assert (tmp_path / "out" / "harden-scripts" / "01-install-deps.sh").read_text().find(
        "pacman"
    ) >= 0

    by_stage = {s.stage: s for s in result.stages}
    assert by_stage[StageId.DISCOVER].status == "ok"
    assert by_stage[StageId.CONFIGURE].status == "ok"
    assert by_stage[StageId.FIREWALL].status == "dry-run"
    assert by_stage[StageId.FAIL2BAN].status == "dry-run"
    assert by_stage[StageId.OPENCANARY].status == "skipped"
    assert by_stage[StageId.DNS].status == "skipped"
    assert by_stage[StageId.CRON].status == "dry-run"
    assert any("Omarchy" in e for e in echoes)


def test_harden_optional_defaults_dry_run(tmp_path):
    opts = HardenOptions(
        output_dir=tmp_path / "out",
        input_path=FIXTURE_SS,
        apply=False,
        hostname="testhost",
        distro=HostDistro(
            family=DistroFamily.UBUNTU,
            id="ubuntu",
            id_like=("debian",),
            pretty_name="Ubuntu",
            package_manager="apt",
        ),
        stages=[
            StageId.DISCOVER,
            StageId.CONFIGURE,
            StageId.OPENCANARY,
            StageId.DNS,
        ],
    )
    result = run_harden(opts, echo=lambda _m: None, confirm=lambda _p, d: d)
    by_stage = {s.stage: s for s in result.stages}
    assert by_stage[StageId.OPENCANARY].status == "dry-run"
    assert by_stage[StageId.DNS].status == "dry-run"
    assert PRIMARY_DNS in by_stage[StageId.DNS].message
