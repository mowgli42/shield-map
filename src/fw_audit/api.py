"""Stable library API for programmatic consumers (e.g. SnarkSentinel).

This module is the supported import surface for analyze / drift-diff /
local-only ruleset drafting. Prefer these helpers over scraping CLI stdout.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Union

from fw_audit.classify.engine import load_policy
from fw_audit.graph.flows import summary_counts
from fw_audit.models import (
    AuditContext,
    Classification,
    Finding,
    Flow,
    Host,
    Listener,
    RulesetArtifact,
    Severity,
)
from fw_audit.pipeline import collect_audit
from fw_audit.report.xml_builder import NS, write_audit_xml

AuditLike = Union[AuditContext, "AnalyzeResult", Path, str]

DEFAULT_GUARDIAN_SOCKET = "/run/guardian.sock"


@dataclass
class AnalyzeResult:
    """Structured posture from live netstat/ss (or export) input."""

    hosts: list[Host]
    listeners: list[Listener]
    connections: list[Any]
    findings: list[Finding]
    flows: list[Flow]
    summary: dict[str, int]
    policy_version: str
    operator: str = "home-lab"
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "operator": self.operator,
            "summary": dict(self.summary),
            "warnings": list(self.warnings),
            "hosts": [asdict(h) for h in self.hosts],
            "listeners": [_listener_dict(ln) for ln in self.listeners],
            "findings": [_finding_dict(f) for f in self.findings],
            "flows": [_flow_dict(fl) for fl in self.flows],
            "connection_count": len(self.connections),
        }


@dataclass
class DiffChange:
    """One drift item between baseline and current posture."""

    kind: str  # added | removed | changed
    subject: str  # listener | finding
    key: str
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DiffResult:
    """Machine-parseable drift report for SnarkSentinel."""

    changes: list[DiffChange]
    baseline_listener_count: int
    current_listener_count: int

    @property
    def has_drift(self) -> bool:
        return bool(self.changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_drift": self.has_drift,
            "baseline_listener_count": self.baseline_listener_count,
            "current_listener_count": self.current_listener_count,
            "changes": [c.to_dict() for c in self.changes],
        }


@dataclass
class LocalOnlyProfile:
    """Artifacts for a local-agent testing firewall profile."""

    hostname: str
    guardian_socket: str
    profile_path: Path
    audit_xml_path: Path
    rulesets: list[RulesetArtifact]
    context: AuditContext

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "guardian_socket": self.guardian_socket,
            "profile_path": str(self.profile_path),
            "audit_xml_path": str(self.audit_xml_path),
            "rulesets": [asdict(r) for r in self.rulesets],
            "remote_inbound_denied": True,
            "loopback_allowed": True,
        }


def analyze(
    input_path: Path | str,
    *,
    hosts_file: Path | str | None = None,
    policy_file: Path | str | None = None,
    operator: str = "home-lab",
) -> AnalyzeResult:
    """Analyze current listeners from netstat/ss exports.

    Returns an in-memory result; does not write rulesets or reports.
    """
    path = Path(input_path)
    hosts = Path(hosts_file) if hosts_file else None
    policy = Path(policy_file) if policy_file else None
    ctx = collect_audit(path, hosts_file=hosts, policy_file=policy, operator=operator)
    return _from_context(ctx)


def diff(
    baseline: AuditLike,
    current: AuditLike,
) -> DiffResult:
    """Diff current posture against a baseline report or analyze result.

    ``baseline`` / ``current`` may be an :class:`AnalyzeResult`,
    :class:`AuditContext`, or path to ``audit-report.xml``.
    """
    base_ctx = _coerce_audit(baseline)
    cur_ctx = _coerce_audit(current)

    base_listeners = {_listener_key(ln): ln for ln in base_ctx.listeners}
    cur_listeners = {_listener_key(ln): ln for ln in cur_ctx.listeners}

    changes: list[DiffChange] = []

    for key, ln in cur_listeners.items():
        if key not in base_listeners:
            changes.append(
                DiffChange(
                    kind="added",
                    subject="listener",
                    key=key,
                    after=_listener_dict(ln),
                    severity=_severity_for_classification(ln.classification),
                )
            )
        else:
            before = base_listeners[key]
            if before.classification != ln.classification:
                changes.append(
                    DiffChange(
                        kind="changed",
                        subject="listener",
                        key=key,
                        before=_listener_dict(before),
                        after=_listener_dict(ln),
                        severity=_severity_for_classification(ln.classification),
                    )
                )

    for key, ln in base_listeners.items():
        if key not in cur_listeners:
            changes.append(
                DiffChange(
                    kind="removed",
                    subject="listener",
                    key=key,
                    before=_listener_dict(ln),
                    severity="info",
                )
            )

    base_findings = {_finding_key(f): f for f in base_ctx.findings}
    cur_findings = {_finding_key(f): f for f in cur_ctx.findings}
    for key, finding in cur_findings.items():
        if key not in base_findings:
            changes.append(
                DiffChange(
                    kind="added",
                    subject="finding",
                    key=key,
                    after=_finding_dict(finding),
                    severity=finding.severity.value,
                )
            )
    for key, finding in base_findings.items():
        if key not in cur_findings:
            changes.append(
                DiffChange(
                    kind="removed",
                    subject="finding",
                    key=key,
                    before=_finding_dict(finding),
                    severity="info",
                )
            )

    changes.sort(key=lambda c: (c.subject, c.kind, c.key))
    return DiffResult(
        changes=changes,
        baseline_listener_count=len(base_listeners),
        current_listener_count=len(cur_listeners),
    )


def generate_local_only(
    output_dir: Path | str,
    *,
    hostname: str = "local-agent",
    os_family: str = "linux",
    guardian_socket: str = DEFAULT_GUARDIAN_SOCKET,
    platforms: list[str] | None = None,
    operator: str = "snarksentinel",
) -> LocalOnlyProfile:
    """Generate a local-only ruleset profile for agent testing.

    Policy intent:
    - loopback inbound allowed
    - guardian Unix socket documented as allowed (host IPC; not nftables-filtered)
    - remote inbound denied (default-deny, no non-loopback allow rules)
    """
    from fw_audit.generators.linux_nftables import generate_nftables
    from fw_audit.generators.windows import generate_windows

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    host = Host(
        id="H001",
        hostname=hostname,
        zone="internal",
        role="agent",
        os_family=os_family,
        tags=["local-only", "snarksentinel"],
    )
    # No remote listeners: generators emit default-deny with loopback accept only.
    listeners: list[Listener] = []
    policy = load_policy()
    policy["init_baseline"] = True
    policy["version"] = "1.0-local-only"
    policy["local_only"] = {
        "loopback_allowed": True,
        "remote_inbound_denied": True,
        "guardian_socket": guardian_socket,
    }

    ctx = AuditContext(
        hosts=[host],
        listeners=listeners,
        policy_version=str(policy["version"]),
        operator=operator,
    )
    ctx.warnings.extend(
        [
            "Local-only profile: remote inbound denied by default policy.",
            f"Guardian Unix socket allowed for local IPC: {guardian_socket}",
            "Unix domain sockets are not filtered by host netfilter; "
            "socket permissions must restrict remote users.",
        ]
    )
    ctx.findings.append(
        Finding(
            code="LOCAL_ONLY_PROFILE",
            severity=Severity.INFO,
            message=(
                "Generated local-only ruleset: loopback allowed, "
                f"guardian socket {guardian_socket}, remote inbound denied"
            ),
            remediation="Apply only on hosts used for local agent testing.",
            host_id=host.id,
        )
    )

    profile = {
        "profile": "local-only",
        "hostname": hostname,
        "os_family": os_family,
        "loopback_allowed": True,
        "remote_inbound_denied": True,
        "guardian_socket": guardian_socket,
        "allowed_binds": ["127.0.0.1", "::1", "lo"],
        "notes": [
            "Intended for SnarkSentinel / local agent testing.",
            "No non-loopback inbound TCP/UDP allows are generated.",
        ],
    }
    import yaml

    profile_path = out / "local-only-profile.yaml"
    profile_path.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")

    host_out = out / hostname
    host_out.mkdir(parents=True, exist_ok=True)
    selected = platforms or (
        ["nftables"] if os_family == "linux" else ["windows"] if os_family == "windows" else ["nftables", "windows"]
    )

    if "nftables" in selected:
        path = host_out / "rules-nftables.conf"
        count = generate_nftables(host, listeners, policy, path, init_mode=True)
        _annotate_local_only_nftables(path, guardian_socket)
        ctx.rulesets.append(
            RulesetArtifact(
                platform="linux",
                format="nftables",
                path=str(path),
                default_deny=True,
                rule_count=count,
                host_id=host.id,
            )
        )
    if "windows" in selected:
        path = host_out / "rules-windows.ps1"
        count = generate_windows(host, listeners, policy, path, init_mode=True)
        _annotate_local_only_windows(path, guardian_socket)
        ctx.rulesets.append(
            RulesetArtifact(
                platform="windows",
                format="powershell",
                path=str(path),
                default_deny=True,
                rule_count=count,
                host_id=host.id,
            )
        )

    xml_path = out / "audit-report.xml"
    write_audit_xml(ctx, xml_path)

    return LocalOnlyProfile(
        hostname=hostname,
        guardian_socket=guardian_socket,
        profile_path=profile_path,
        audit_xml_path=xml_path,
        rulesets=list(ctx.rulesets),
        context=ctx,
    )


def _from_context(ctx: AuditContext) -> AnalyzeResult:
    return AnalyzeResult(
        hosts=list(ctx.hosts),
        listeners=list(ctx.listeners),
        connections=list(ctx.connections),
        findings=list(ctx.findings),
        flows=list(ctx.flows),
        summary=summary_counts(ctx.flows),
        policy_version=ctx.policy_version,
        operator=ctx.operator,
        warnings=list(ctx.warnings),
    )


def _coerce_audit(value: AuditLike) -> AuditContext:
    if isinstance(value, AuditContext):
        return value
    if isinstance(value, AnalyzeResult):
        return AuditContext(
            hosts=list(value.hosts),
            listeners=list(value.listeners),
            connections=list(value.connections),
            findings=list(value.findings),
            flows=list(value.flows),
            policy_version=value.policy_version,
            operator=value.operator,
            warnings=list(value.warnings),
        )
    return load_audit_xml(Path(value))


def load_audit_xml(path: Path) -> AuditContext:
    """Load listeners/findings from an audit-report.xml for library consumers."""
    tree = ET.parse(path)
    root = tree.getroot()
    ns = {"fa": NS}

    hosts: list[Host] = []
    for h in root.findall(".//fa:Inventory/fa:Host", ns):
        hosts.append(
            Host(
                id=h.get("id", "H001"),
                hostname=h.get("hostname", "unknown"),
                zone=h.get("zone", "internal"),
                role=h.get("role", "server"),
            )
        )

    listeners: list[Listener] = []
    for el in root.findall(".//fa:ObservedListeners/fa:Listener", ns):
        svc = el.find("fa:Service", ns)
        listeners.append(
            Listener(
                host_id=el.get("hostRef", "H001"),
                protocol=el.get("protocol", "tcp"),
                port=int(el.get("port", "0")),
                bind_address=el.get("bindAddress", "0.0.0.0"),
                classification=Classification(el.get("classification", "unknown")),
                service_name=svc.text if svc is not None and svc.text else "",
            )
        )

    findings: list[Finding] = []
    for el in root.findall(".//fa:Findings/fa:Finding", ns):
        text = (el.text or "").split("|")[0].strip()
        findings.append(
            Finding(
                code=el.get("code", "UNKNOWN"),
                severity=Severity(el.get("severity", "info")),
                message=text,
                remediation="",
                host_id=el.get("hostRef") or None,
            )
        )

    meta_pv = root.find(".//fa:Metadata/fa:PolicyVersion", ns)
    meta_op = root.find(".//fa:Metadata/fa:Operator", ns)
    return AuditContext(
        hosts=hosts or [Host(id="H001", hostname="unknown")],
        listeners=listeners,
        findings=findings,
        policy_version=meta_pv.text if meta_pv is not None and meta_pv.text else "1.0",
        operator=meta_op.text if meta_op is not None and meta_op.text else "home-lab",
    )


def _listener_key(ln: Listener) -> str:
    return f"{ln.host_id}|{ln.protocol.lower()}|{ln.port}|{ln.bind_address}"


def _finding_key(finding: Finding) -> str:
    return (
        f"{finding.code}|{finding.host_id or ''}|"
        f"{finding.listener_protocol or ''}|{finding.listener_port or ''}|{finding.message}"
    )


def _listener_dict(ln: Listener) -> dict[str, Any]:
    return {
        "host_id": ln.host_id,
        "protocol": ln.protocol,
        "port": ln.port,
        "bind_address": ln.bind_address,
        "classification": ln.classification.value
        if isinstance(ln.classification, Classification)
        else str(ln.classification),
        "service_name": ln.service_name,
        "process_name": ln.process_name,
        "allowed_sources": list(ln.allowed_sources),
    }


def _finding_dict(finding: Finding) -> dict[str, Any]:
    return {
        "code": finding.code,
        "severity": finding.severity.value
        if isinstance(finding.severity, Severity)
        else str(finding.severity),
        "message": finding.message,
        "remediation": finding.remediation,
        "host_id": finding.host_id,
        "listener_port": finding.listener_port,
        "listener_protocol": finding.listener_protocol,
    }


def _flow_dict(flow: Flow) -> dict[str, Any]:
    return {
        "id": flow.id,
        "server_host_id": flow.server_host_id,
        "protocol": flow.protocol,
        "port": flow.port,
        "classification": flow.classification.value
        if isinstance(flow.classification, Classification)
        else str(flow.classification),
        "service_name": flow.service_name,
        "server_zone": flow.server_zone,
        "client_zone": flow.client_zone,
        "flow_kind": flow.flow_kind,
    }


def _severity_for_classification(classification: Classification | str) -> str:
    value = (
        classification.value
        if isinstance(classification, Classification)
        else str(classification)
    )
    return {
        "unsafe": "critical",
        "risky": "high",
        "preferred": "info",
        "unknown": "medium",
    }.get(value, "info")


def _annotate_local_only_nftables(path: Path, guardian_socket: str) -> None:
    text = path.read_text(encoding="utf-8")
    note = (
        f"# Local-only profile: iif lo accept; remote inbound denied (policy drop)\n"
        f"# Guardian Unix socket (local IPC, not nftables-filtered): {guardian_socket}\n"
    )
    if "# Mode:" in text:
        text = text.replace("# Mode:", note + "# Mode:", 1)
    else:
        text = note + text
    path.write_text(text, encoding="utf-8")


def _annotate_local_only_windows(path: Path, guardian_socket: str) -> None:
    text = path.read_text(encoding="utf-8")
    note = (
        f"# Local-only profile: default inbound Block; no remote allow rules\n"
        f"# Guardian named pipe / Unix socket for local IPC: {guardian_socket}\n"
    )
    if "# Mode:" in text:
        text = text.replace("# Mode:", note + "# Mode:", 1)
    else:
        text = note + text
    path.write_text(text, encoding="utf-8")


# Re-export names useful for typing at call sites without deep imports.
__all__ = [
    "AnalyzeResult",
    "DiffChange",
    "DiffResult",
    "LocalOnlyProfile",
    "DEFAULT_GUARDIAN_SOCKET",
    "analyze",
    "diff",
    "generate_local_only",
    "load_audit_xml",
]
