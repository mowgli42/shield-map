"""Orchestrate ingest, classify, report, and ruleset generation."""

from __future__ import annotations

import hashlib
from pathlib import Path

from fw_audit.classify.engine import ClassificationEngine, load_policy
from fw_audit.graph.cross_zone import cross_zone_findings
from fw_audit.graph.flows import build_flows
from fw_audit.graph.ipmap import build_ip_to_host
from fw_audit.models import AuditContext, Host, HostNetworkProfile, InputRecord
from fw_audit.network.outbound import analyze_outbound_whitelist, build_outbound_service_uses
from fw_audit.network.profile_audit import audit_network_profile
from fw_audit.parsers.detector import parse_file
from fw_audit.parsers.network_profile import detect_network_profile_parser, parse_network_profile_file
from fw_audit.policy.loader import load_hosts, load_zone_policy
from fw_audit.report.dot_export import write_dot

_PROFILE_STEMS = ("ipconfig", "network-linux", "network-profile", "network")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_profile_file(path: Path) -> bool:
    name = path.stem.lower()
    return any(name.startswith(s) for s in _PROFILE_STEMS) or name == "ipconfig"


def _discover_inputs(path: Path) -> tuple[list[tuple[Path, str]], list[tuple[Path, str]]]:
    """Return (netstat_files, profile_files) as (path, host_key) lists."""
    netstat_files: list[tuple[Path, str]] = []
    profile_files: list[tuple[Path, str]] = []

    def classify_file(f: Path, host_key: str) -> None:
        if _is_profile_file(f):
            profile_files.append((f, host_key))
            return
        if f.suffix not in (".txt", ".csv", ".log"):
            return
        text = f.read_text(encoding="utf-8", errors="replace")
        if detect_network_profile_parser(f.name, text):
            profile_files.append((f, host_key))
        else:
            netstat_files.append((f, host_key))

    if path.is_file():
        if _is_profile_file(path):
            profile_files.append((path, path.stem))
        else:
            netstat_files.append((path, path.stem))
        return netstat_files, profile_files

    for child in sorted(path.iterdir()):
        if child.is_dir() and child.name not in ("out", "output"):
            for f in sorted(child.iterdir()):
                if f.is_file():
                    classify_file(f, child.name)
        elif child.is_file():
            classify_file(child, path.stem)

    return netstat_files, profile_files


def _resolve_host(hosts_map: dict[str, Host], host_key: str, ctx_hosts: list[Host]) -> Host:
    host = hosts_map.get(host_key) or hosts_map.get(host_key.replace("_", "-"))
    if host:
        return host
    hid = f"H{len(ctx_hosts) + 1:03d}"
    host = Host(id=hid, hostname=host_key, zone="internal")
    hosts_map[host_key] = host
    ctx_hosts.append(host)
    return host


def run_audit(
    input_path: Path,
    output_dir: Path,
    hosts_file: Path | None = None,
    policy_file: Path | None = None,
    operator: str = "home-lab",
    platforms: list[str] | None = None,
    export_dot: bool = True,
) -> AuditContext:
    from fw_audit.generators.cisco_ios import generate_cisco_ios
    from fw_audit.generators.linux_nftables import generate_nftables
    from fw_audit.generators.windows import generate_windows
    from fw_audit.report.xml_builder import write_audit_xml

    output_dir.mkdir(parents=True, exist_ok=True)
    hosts_map = load_hosts(hosts_file)
    zone_policy = load_zone_policy(hosts_file)
    policy = load_policy(policy_file)
    engine = ClassificationEngine(policy)

    ctx = AuditContext(policy_version=str(policy.get("version", "1.0")), operator=operator)
    ctx.hosts = list({h.id: h for h in hosts_map.values() if h.id.startswith("H")}.values())
    if not ctx.hosts:
        ctx.hosts = [hosts_map[list(hosts_map)[0]]]

    netstat_files, profile_files = _discover_inputs(input_path)
    all_listeners = []
    all_connections = []
    profiles_by_host: dict[str, HostNetworkProfile] = {}

    for file_path, host_key in profile_files:
        host = _resolve_host(hosts_map, host_key, ctx.hosts)
        text = file_path.read_text(encoding="utf-8", errors="replace")
        profile = parse_network_profile_file(text, host.id, file_path.name, str(file_path))
        if profile:
            profiles_by_host[host.id] = profile
            ctx.inputs.append(
                InputRecord(
                    path=str(file_path),
                    checksum_sha256=_sha256(file_path),
                    host_id=host.id,
                    parser="network_profile",
                )
            )

    for file_path, host_key in netstat_files:
        host = _resolve_host(hosts_map, host_key, ctx.hosts)
        listeners, connections, parser_name = parse_file(file_path, host.id)
        all_listeners.extend(listeners)
        all_connections.extend(connections)

        ctx.inputs.append(
            InputRecord(
                path=str(file_path),
                checksum_sha256=_sha256(file_path),
                host_id=host.id,
                parser=parser_name,
            )
        )

    ctx.listeners = all_listeners
    ctx.connections = all_connections
    ctx.network_profiles = list(profiles_by_host.values())

    hosts_by_id = {h.id: h for h in ctx.hosts}
    ip_map = build_ip_to_host(hosts_map)

    ctx.findings = engine.apply_to_listeners(ctx.listeners, hosts_by_id)
    ctx.flows = build_flows(
        ctx.listeners,
        hosts_by_id,
        connections=ctx.connections,
        ip_map=ip_map,
        engine=engine,
    )
    ctx.findings.extend(cross_zone_findings(ctx.flows, hosts_by_id, zone_policy))

    for host in ctx.hosts:
        profile = profiles_by_host.get(host.id)
        if profile:
            ctx.findings.extend(audit_network_profile(profile, host, policy))

        uses = build_outbound_service_uses(ctx.connections, host.id, engine, policy)
        ctx.outbound_services.extend(uses)
        ctx.findings.extend(analyze_outbound_whitelist(uses, policy))

    platforms = platforms or ["windows", "nftables"]
    strict_outbound = policy.get("outbound_whitelist", {}).get("enforce", False)

    for host in ctx.hosts:
        host_listeners = [ln for ln in ctx.listeners if ln.host_id == host.id]
        if not host_listeners and host.id not in profiles_by_host:
            continue
        host_out = output_dir / host.hostname
        host_out.mkdir(parents=True, exist_ok=True)

        if "windows" in platforms:
            out = host_out / "rules-windows.ps1"
            count = generate_windows(host, host_listeners, policy, out)
            ctx.rulesets.append(_artifact("windows", "powershell", out, host.id, count))
        if "nftables" in platforms:
            out = host_out / "rules-nftables.conf"
            count = generate_nftables(
                host,
                host_listeners,
                policy,
                out,
                strict_outbound=strict_outbound and host.role in ("workstation", "client"),
            )
            ctx.rulesets.append(_artifact("linux", "nftables", out, host.id, count))
        if "cisco" in platforms:
            out = host_out / "rules-cisco-ios.acl"
            count = generate_cisco_ios(host, host_listeners, policy, out)
            ctx.rulesets.append(_artifact("cisco", "ios-acl", out, host.id, count))

    xml_path = output_dir / "audit-report.xml"
    write_audit_xml(ctx, xml_path)

    if export_dot:
        dot_path = output_dir / "network-dataflow.dot"
        write_dot(ctx, dot_path)

    if strict_outbound:
        ctx.warnings.append(
            "outbound_whitelist.enforce=true: review UNAPPROVED_OUTBOUND findings; "
            "Linux nftables output chain restricted for clients. "
            "Windows app-level whitelist requires WDAC/AppLocker beyond port rules."
        )

    return ctx


def _artifact(platform: str, fmt: str, path: Path, host_id: str, count: int):
    from fw_audit.models import RulesetArtifact

    return RulesetArtifact(
        platform=platform,
        format=fmt,
        path=str(path),
        default_deny=True,
        rule_count=count,
        host_id=host_id,
    )
