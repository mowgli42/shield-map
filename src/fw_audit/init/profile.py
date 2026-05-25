"""Build planned listeners and policy from host intent (Phase 1a)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from fw_audit.models import Classification, Host, Listener

_SERVICES_PATH = Path(__file__).resolve().parent / "services.yaml"


@dataclass
class HostIntent:
    hostname: str
    host_type: str  # client | server | both
    os_family: str  # windows | linux
    zone: str = "internal"
    mgmt_cidr: str = "192.168.0.0/16"
    services: list[str] = field(default_factory=list)
    allow_rdp: bool = False
    web_mode: str = "https-only"  # https-only | http-and-https
    internet_facing: bool = False
    allow_outbound_dns_https: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "host_type": self.host_type,
            "os_family": self.os_family,
            "zone": self.zone,
            "mgmt_cidr": self.mgmt_cidr,
            "services": self.services,
            "allow_rdp": self.allow_rdp,
            "web_mode": self.web_mode,
            "internet_facing": self.internet_facing,
            "allow_outbound_dns_https": self.allow_outbound_dns_https,
        }


def load_services_catalog() -> dict[str, Any]:
    with _SERVICES_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _bind_for_zone(zone: str, internet_facing: bool) -> str:
    if internet_facing or zone in ("dmz", "public"):
        return "0.0.0.0"
    return "0.0.0.0"  # rules restrict by source CIDR; bind comment in manifest


def _classification(name: str) -> Classification:
    return Classification(name)


def build_listeners_from_intent(intent: HostIntent, host_id: str = "H001") -> tuple[list[Listener], dict[str, Any]]:
    """Return listeners and a policy dict tuned for init (approve planned risky ports)."""
    catalog = load_services_catalog()
    listeners: list[Listener] = []
    approved_risky: list[dict[str, Any]] = []
    bind = _bind_for_zone(intent.zone, intent.internet_facing)
    source = str(Path("init-wizard"))

    def add_port(
        proto: str,
        port: int,
        classification: str,
        service: str,
        restrict_source: bool = False,
        direction: str = "inbound",
    ) -> None:
        cls = _classification(classification)
        allowed = [intent.mgmt_cidr] if restrict_source else []
        listeners.append(
            Listener(
                host_id=host_id,
                protocol=proto,
                port=port,
                bind_address=bind,
                state="planned",
                classification=cls,
                service_name=service,
                observed_in_file=source,
                allowed_sources=allowed,
            )
        )
        if cls == Classification.RISKY:
            approved_risky.append({"proto": proto, "port": port, "service": service})

    host_type = intent.host_type.lower()
    is_client = host_type in ("client", "workstation", "both")
    is_server = host_type in ("server", "both")

    if is_client and intent.allow_rdp:
        for port_def in catalog.get("client_options", {}).get("rdp", {}).get("ports", []):
            add_port(
                port_def["proto"],
                int(port_def["port"]),
                port_def["classification"],
                "rdp",
                restrict_source=port_def.get("restrict_source", False),
            )

    if is_server or host_type == "both":
        service_defs = catalog.get("services", {})
        for svc_id in intent.services:
            svc = service_defs.get(svc_id)
            if not svc:
                continue
            for port_def in svc.get("ports", []):
                if port_def.get("optional") and port_def.get("id") == "http":
                    if intent.web_mode != "http-and-https":
                        continue
                add_port(
                    port_def["proto"],
                    int(port_def["port"]),
                    port_def["classification"],
                    svc_id,
                    restrict_source=port_def.get("restrict_source", False),
                )

    if is_client and intent.allow_outbound_dns_https:
        for port_def in catalog.get("baseline", {}).get("client_outbound", []):
            listeners.append(
                Listener(
                    host_id=host_id,
                    protocol=port_def["proto"],
                    port=int(port_def["port"]),
                    bind_address="0.0.0.0",
                    state="planned-outbound",
                    classification=Classification.PREFERRED,
                    service_name=port_def.get("service", "outbound"),
                    observed_in_file=source,
                )
            )

    policy = {
        "version": "1.0-init",
        "default_unknown": "risky",
        "approved_risky": approved_risky,
        "init_baseline": True,
        "mgmt_cidr": intent.mgmt_cidr,
    }
    return listeners, policy


def host_from_intent(intent: HostIntent, host_id: str = "H001") -> Host:
    role = "workstation" if intent.host_type.lower() in ("client", "workstation") else "server"
    if intent.host_type.lower() == "both":
        role = "server"
    return Host(
        id=host_id,
        hostname=intent.hostname,
        zone=intent.zone,
        role=role,
        os_family=intent.os_family,
        tags=["init-wizard", "phase-1a"],
    )


def save_intent(intent: HostIntent, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(intent.to_dict(), fh, default_flow_style=False, sort_keys=False)


def load_intent(path: Path) -> HostIntent:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return HostIntent(
        hostname=str(data.get("hostname", "localhost")),
        host_type=str(data.get("host_type", "client")),
        os_family=str(data.get("os_family", data.get("os", "linux"))),
        zone=str(data.get("zone", "internal")),
        mgmt_cidr=str(data.get("mgmt_cidr", "192.168.0.0/16")),
        services=[str(s) for s in data.get("services", [])],
        allow_rdp=bool(data.get("allow_rdp", False)),
        web_mode=str(data.get("web_mode", "https-only")),
        internet_facing=bool(data.get("internet_facing", False)),
        allow_outbound_dns_https=bool(data.get("allow_outbound_dns_https", True)),
    )
