"""Build NetworkAuditReport XML."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from fw_audit import __version__
from fw_audit.graph.flows import summary_counts
from fw_audit.models import AuditContext, Classification

NS = "urn:fw-audit:network-audit:1"
ET.register_namespace("", NS)


def _q(tag: str) -> str:
    return f"{{{NS}}}{tag}"


def write_audit_xml(ctx: AuditContext, output_path: Path) -> None:
    root = ET.Element(
        _q("NetworkAuditReport"),
        {
            "version": "1.0",
            "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "toolVersion": __version__,
        },
    )

    meta = ET.SubElement(root, _q("Metadata"))
    ET.SubElement(meta, _q("PolicyVersion")).text = ctx.policy_version
    ET.SubElement(meta, _q("Operator")).text = ctx.operator
    for inp in ctx.inputs:
        cs = ET.SubElement(
            meta,
            _q("InputChecksum"),
            {"algorithm": "sha256", "file": inp.path},
        )
        cs.text = inp.checksum_sha256

    compliance = ET.SubElement(root, _q("ComplianceMapping"))
    cis = ET.SubElement(
        compliance, _q("Framework"), {"name": "CIS Controls", "version": "8.1"}
    )
    for sid, status, note in [
        ("4.4", "addressed", "Server firewall rules generated"),
        ("9.4", "addressed", "Default-deny rulesets emitted"),
        ("12.4", "partial" if _has_unsafe(ctx) else "addressed", "Unsafe port findings"),
    ]:
        sg = ET.SubElement(cis, _q("Safeguard"), {"id": sid, "status": status})
        sg.text = note

    nist = ET.SubElement(
        compliance, _q("Framework"), {"name": "NIST 800-53", "version": "rev5"}
    )
    for cid, status, note in [
        ("SC-7(5)", "addressed", "Deny-by-default generator policy"),
        ("SC-7(12)", "addressed", "Host-based rules for Windows/Linux"),
        ("AC-4", "addressed", "Flow matrix documented in report"),
    ]:
        ctrl = ET.SubElement(nist, _q("Control"), {"id": cid, "status": status})
        ctrl.text = note

    summary = summary_counts(ctx.flows)
    exec_sum = ET.SubElement(root, _q("ExecutiveSummary"))
    for cat in Classification:
        ET.SubElement(exec_sum, _q("Count"), {"classification": cat.value}).text = str(
            summary.get(cat.value, 0)
        )

    inventory = ET.SubElement(root, _q("Inventory"))
    for host in ctx.hosts:
        h = ET.SubElement(
            inventory,
            _q("Host"),
            {"id": host.id, "hostname": host.hostname, "zone": host.zone, "role": host.role},
        )
        if host.owner:
            ET.SubElement(h, _q("Owner")).text = host.owner

    observed = ET.SubElement(root, _q("ObservedListeners"))
    for ln in ctx.listeners:
        el = ET.SubElement(
            observed,
            _q("Listener"),
            {
                "hostRef": ln.host_id,
                "protocol": ln.protocol,
                "port": str(ln.port),
                "bindAddress": ln.bind_address,
                "classification": ln.classification.value,
            },
        )
        if ln.service_name:
            ET.SubElement(el, _q("Service")).text = ln.service_name
        if ln.process_name:
            ET.SubElement(el, _q("Process")).text = ln.process_name

    flows_el = ET.SubElement(root, _q("Flows"))
    for flow in ctx.flows:
        f = ET.SubElement(
            flows_el,
            _q("Flow"),
            {"id": flow.id, "classification": flow.classification.value, "flowKind": flow.flow_kind},
        )
        client = ET.SubElement(
            f,
            _q("Client"),
            {"hostRef": flow.client_host_id or "", "zone": flow.client_zone, "address": ""},
        )
        if flow.client_address:
            client.set("address", flow.client_address)
        ET.SubElement(
            f,
            _q("Server"),
            {
                "hostRef": flow.server_host_id,
                "zone": flow.server_zone,
                "address": flow.server_address,
            },
        )
        ET.SubElement(
            f,
            _q("Service"),
            {
                "protocol": flow.protocol,
                "port": str(flow.port),
                "name": flow.service_name,
            },
        )


    profiles_el = ET.SubElement(root, _q("HostNetworkProfiles"))
    for prof in ctx.network_profiles:
        hp = ET.SubElement(profiles_el, _q("HostProfile"), {"hostRef": prof.host_id})
        if prof.default_gateway:
            ET.SubElement(hp, _q("DefaultGateway")).text = prof.default_gateway
        dns_el = ET.SubElement(hp, _q("DnsServers"))
        for dns in prof.dns_servers:
            ET.SubElement(dns_el, _q("Server")).text = dns
        ifaces_el = ET.SubElement(hp, _q("Interfaces"))
        for iface in prof.interfaces:
            ET.SubElement(
                ifaces_el,
                _q("Interface"),
                {
                    "name": iface.name,
                    "kind": iface.kind,
                    "state": iface.state,
                    "gateway": iface.gateway or "",
                },
            ).text = ", ".join(iface.ipv4_addresses) or iface.description

    outbound_el = ET.SubElement(root, _q("OutboundClientServices"))
    for use in ctx.outbound_services:
        ET.SubElement(
            outbound_el,
            _q("ServiceUse"),
            {
                "hostRef": use.host_id,
                "process": use.process_name,
                "protocol": use.protocol,
                "remoteAddress": use.remote_address,
                "remotePort": str(use.remote_port),
                "classification": use.classification.value,
                "approved": "true" if use.approved else "false",
                "service": use.service_name,
            },
        )

    findings_el = ET.SubElement(root, _q("Findings"))
    for finding in sorted(
        ctx.findings, key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value)
    ):
        ET.SubElement(
            findings_el,
            _q("Finding"),
            {
                "code": finding.code,
                "severity": finding.severity.value,
                "hostRef": finding.host_id or "",
            },
        ).text = f"{finding.message} | Remediation: {finding.remediation}"

    artifacts = ET.SubElement(root, _q("RulesetArtifacts"))
    for art in ctx.rulesets:
        ET.SubElement(
            artifacts,
            _q("Artifact"),
            {
                "platform": art.platform,
                "format": art.format,
                "path": art.path,
                "defaultDeny": "true" if art.default_deny else "false",
                "ruleCount": str(art.rule_count),
                "hostRef": art.host_id,
            },
        )

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)


def _has_unsafe(ctx: AuditContext) -> bool:
    return any(ln.classification == Classification.UNSAFE for ln in ctx.listeners)
