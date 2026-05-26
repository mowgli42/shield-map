"""Port/protocol classification against built-in and user policy."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from fw_audit.models import Classification, Finding, Host, Listener, Severity

_POLICY_KEY = (str, str)  # (proto, port) -> category name


def _defaults_path() -> Path:
    return Path(__file__).resolve().parent / "defaults.yaml"


def load_policy(path: Path | None = None) -> dict[str, Any]:
    """Load policy YAML; user file merges over packaged defaults."""
    with _defaults_path().open(encoding="utf-8") as fh:
        policy: dict[str, Any] = yaml.safe_load(fh) or {}
    if path and path.is_file():
        with path.open(encoding="utf-8") as fh:
            user = yaml.safe_load(fh) or {}
        for key in ("categories", "rules", "approved_risky", "outbound_whitelist"):
            if key in user:
                if key == "categories":
                    for cat, entries in user.get("categories", {}).items():
                        policy.setdefault("categories", {}).setdefault(cat, [])
                        policy["categories"][cat].extend(entries)
                elif key == "outbound_whitelist":
                    policy.setdefault("outbound_whitelist", {}).update(user[key])
                else:
                    policy[key] = user[key]
        if "version" in user:
            policy["version"] = user["version"]
        if "default_unknown" in user:
            policy["default_unknown"] = user["default_unknown"]
    return policy


class ClassificationEngine:
    def __init__(self, policy: dict[str, Any] | None = None) -> None:
        self.policy = policy or load_policy()
        self._lookup: dict[tuple[str, int], str] = {}
        for category, entries in self.policy.get("categories", {}).items():
            for entry in entries:
                proto = str(entry.get("proto", "tcp")).lower()
                port = int(entry["port"])
                self._lookup[(proto, port)] = category
        default_unknown = self.policy.get("default_unknown", "risky")
        self._default_unknown = Classification(default_unknown)

    def classify_listener(
        self, listener: Listener, host: Host | None = None
    ) -> Classification:
        key = (listener.protocol.lower(), listener.port)
        category = self._lookup.get(key)
        if category:
            listener.service_name = self._service_name(key)
            return Classification(category)

        for rule in self.policy.get("rules", []):
            match = rule.get("match", {})
            if (
                str(match.get("proto", "")).lower() == listener.protocol.lower()
                and int(match.get("port", -1)) == listener.port
            ):
                if self._rule_applies(rule, listener, host):
                    return Classification(rule["classification"])

        listener.service_name = listener.service_name or f"port-{listener.port}"
        return self._default_unknown

    def _service_name(self, key: tuple[str, int]) -> str:
        for _cat, entries in self.policy.get("categories", {}).items():
            for entry in entries:
                if (
                    str(entry.get("proto", "tcp")).lower() == key[0]
                    and int(entry["port"]) == key[1]
                ):
                    return str(entry.get("service", f"port-{key[1]}"))
        return f"port-{key[1]}"

    def _rule_applies(
        self, rule: dict[str, Any], listener: Listener, host: Host | None
    ) -> bool:
        condition = rule.get("condition", "")
        if not condition or not host:
            return True
        zone = host.zone
        if "source_zone == public" in condition:
            return zone == "public" or self._is_public_bind(listener.bind_address)
        if "source_zone != mgmt" in condition:
            return zone != "mgmt"
        return True

    @staticmethod
    def _is_public_bind(addr: str) -> bool:
        return addr in ("0.0.0.0", "::", "*", "0.0.0.0:*", "[::]")

    def apply_to_listeners(
        self, listeners: list[Listener], hosts: dict[str, Host]
    ) -> list[Finding]:
        findings: list[Finding] = []
        approved = self.policy.get("approved_risky", [])

        for listener in listeners:
            host = hosts.get(listener.host_id)
            classification = self.classify_listener(listener, host)
            listener.classification = classification

            if classification == Classification.UNSAFE:
                findings.append(
                    Finding(
                        code="UNSAFE_PORT_LISTENING",
                        severity=Severity.CRITICAL,
                        message=(
                            f"Unsafe service {listener.protocol}/{listener.port} "
                            f"listening on {listener.bind_address}"
                        ),
                        remediation="Block port and disable service; align with CIS 12.4.",
                        host_id=listener.host_id,
                        listener_port=listener.port,
                        listener_protocol=listener.protocol,
                    )
                )
            elif classification == Classification.RISKY and self._is_public_bind(
                listener.bind_address
            ):
                findings.append(
                    Finding(
                        code="RISKY_PORT_PUBLIC_BIND",
                        severity=Severity.HIGH,
                        message=(
                            f"Risky port {listener.protocol}/{listener.port} bound to all interfaces"
                        ),
                        remediation="Bind to internal IP or restrict with host firewall.",
                        host_id=listener.host_id,
                        listener_port=listener.port,
                        listener_protocol=listener.protocol,
                    )
                )
            elif classification == Classification.UNKNOWN:
                findings.append(
                    Finding(
                        code="UNKNOWN_PORT",
                        severity=Severity.LOW,
                        message=f"Unknown port {listener.protocol}/{listener.port} requires review",
                        remediation="Add to policy.yaml categories or block.",
                        host_id=listener.host_id,
                        listener_port=listener.port,
                        listener_protocol=listener.protocol,
                    )
                )
            elif classification == Classification.RISKY:
                key = f"{listener.protocol}/{listener.port}"
                if key not in approved and not self._approved_port(approved, listener):
                    findings.append(
                        Finding(
                            code="RISKY_PORT_UNAPPROVED",
                            severity=Severity.MEDIUM,
                            message=f"Risky port {key} not in approved_risky list",
                            remediation="Add to policy approved_risky with source CIDRs or block.",
                            host_id=listener.host_id,
                            listener_port=listener.port,
                            listener_protocol=listener.protocol,
                        )
                    )
        return findings

    @staticmethod
    def _approved_port(approved: list[Any], listener: Listener) -> bool:
        for item in approved:
            if isinstance(item, dict):
                if (
                    str(item.get("proto", "")).lower() == listener.protocol.lower()
                    and int(item.get("port", -1)) == listener.port
                ):
                    return True
            elif isinstance(item, str) and item == f"{listener.protocol}/{listener.port}":
                return True
        return False
