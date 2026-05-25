import xml.etree.ElementTree as ET
from pathlib import Path

from fw_audit.pipeline import run_audit

FIXTURES = Path(__file__).parent / "fixtures"
NS = {"fa": "urn:fw-audit:network-audit:1"}


def test_all_in_one_pipeline(tmp_path):
    out = tmp_path / "out"
    ctx = run_audit(
        FIXTURES / "netstat-windows.txt",
        out,
        platforms=["windows", "nftables"],
    )
    assert len(ctx.listeners) >= 4
    assert (out / "audit-report.xml").is_file()
    ps1 = list(out.rglob("rules-windows.ps1"))
    nft = list(out.rglob("rules-nftables.conf"))
    assert ps1
    assert nft
    assert "default-deny" in ps1[0].read_text().lower() or "Block" in ps1[0].read_text()

    root = ET.parse(out / "audit-report.xml").getroot()
    tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    assert tag == "NetworkAuditReport"
    flows = root.findall(".//fa:Flow", NS)
    assert len(flows) >= 1
    unsafe = root.findall(".//fa:Flow[@classification='unsafe']", NS)
    assert len(unsafe) >= 1
