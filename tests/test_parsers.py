from pathlib import Path

from fw_audit.parsers.netstat_windows import parse_netstat_windows
from fw_audit.parsers.ss_linux import parse_ss_linux

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_windows_netstat():
    text = (FIXTURES / "netstat-windows.txt").read_text()
    listeners = parse_netstat_windows(text, "H001", "netstat-windows.txt")
    ports = sorted((ln.protocol, ln.port) for ln in listeners)
    assert ("tcp", 443) in ports
    assert ("tcp", 23) in ports
    assert ("udp", 53) in ports


def test_parse_ss_linux():
    text = (FIXTURES / "ss-linux.txt").read_text()
    listeners = parse_ss_linux(text, "H002", "ss-linux.txt")
    ports = [ln.port for ln in listeners]
    assert 22 in ports
    assert 80 in ports
    assert 6379 in ports
    redis = next(ln for ln in listeners if ln.port == 6379)
    assert redis.process_name == "redis"
