"""Canonical data model for network audit pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Classification(str, Enum):
    PREFERRED = "preferred"
    RISKY = "risky"
    UNSAFE = "unsafe"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Host:
    id: str
    hostname: str
    zone: str = "internal"
    role: str = "server"
    os_family: str = "unknown"
    owner: str = ""
    tags: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)


@dataclass
class Listener:
    host_id: str
    protocol: str
    port: int
    bind_address: str
    state: str = "listening"
    process_name: Optional[str] = None
    observed_in_file: str = ""
    line_number: int = 0
    classification: Classification = Classification.UNKNOWN
    service_name: str = ""
    allowed_sources: list[str] = field(default_factory=list)


@dataclass
class Connection:
    """Active session (e.g. TCP ESTABLISHED) observed on a host."""

    host_id: str
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    observed_in_file: str = ""
    line_number: int = 0


@dataclass
class Flow:
    id: str
    server_host_id: str
    server_address: str
    protocol: str
    port: int
    classification: Classification
    service_name: str = ""
    client_host_id: Optional[str] = None
    client_address: Optional[str] = None
    client_zone: str = "unknown"
    server_zone: str = "internal"
    direction: str = "inbound"
    flow_kind: str = "listener"  # listener | session


@dataclass
class Finding:
    code: str
    severity: Severity
    message: str
    remediation: str
    host_id: Optional[str] = None
    listener_port: Optional[int] = None
    listener_protocol: Optional[str] = None


@dataclass
class InputRecord:
    path: str
    checksum_sha256: str
    host_id: str
    parser: str


@dataclass
class RulesetArtifact:
    platform: str
    format: str
    path: str
    default_deny: bool
    rule_count: int
    host_id: str


@dataclass
class AuditContext:
    hosts: list[Host] = field(default_factory=list)
    listeners: list[Listener] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    inputs: list[InputRecord] = field(default_factory=list)
    rulesets: list[RulesetArtifact] = field(default_factory=list)
    policy_version: str = "1.0"
    operator: str = "home-lab"
    warnings: list[str] = field(default_factory=list)
