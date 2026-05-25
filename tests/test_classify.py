from fw_audit.classify.engine import ClassificationEngine, load_policy
from fw_audit.models import Classification, Host, Listener


def test_classify_preferred_and_unsafe():
    engine = ClassificationEngine(load_policy())
    host = Host(id="H001", hostname="test", zone="internal")

    ssh = Listener(host_id="H001", protocol="tcp", port=22, bind_address="0.0.0.0")
    telnet = Listener(host_id="H001", protocol="tcp", port=23, bind_address="0.0.0.0")

    assert engine.classify_listener(ssh, host) == Classification.PREFERRED
    assert engine.classify_listener(telnet, host) == Classification.UNSAFE


def test_findings_for_unsafe():
    engine = ClassificationEngine(load_policy())
    host = Host(id="H001", hostname="test", zone="public")
    listeners = [
        Listener(host_id="H001", protocol="tcp", port=23, bind_address="0.0.0.0"),
    ]
    findings = engine.apply_to_listeners(listeners, {"H001": host})
    assert any(f.code == "UNSAFE_PORT_LISTENING" for f in findings)
