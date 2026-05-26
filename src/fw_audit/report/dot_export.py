"""Export network flows as Graphviz DOT for dataflow diagrams."""

from __future__ import annotations

from pathlib import Path

from fw_audit.models import AuditContext, Flow, Host


def write_dot(ctx: AuditContext, output_path: Path) -> None:
    hosts_by_id = {h.id: h for h in ctx.hosts}
    lines = [
        "digraph network_audit {",
        '  rankdir=LR;',
        '  node [shape=box, style=filled, fontname="Helvetica"];',
        '  edge [fontname="Helvetica", fontsize=10];',
        "",
    ]

    zone_colors = {
        "internal": "#e3f2fd",
        "dmz": "#fff8e1",
        "public": "#ffebee",
        "mgmt": "#e8f5e9",
    }

    for host in ctx.hosts:
        color = zone_colors.get(host.zone, "#f5f5f5")
        label = f"{host.hostname}\\n({host.zone})"
        lines.append(
            f'  "{host.id}" [label="{label}", fillcolor="{color}"];'
        )

    seen_edges: set[tuple[str, str, str]] = set()
    for flow in ctx.flows:
        if flow.flow_kind == "listener":
            continue
        if not flow.client_host_id:
            continue
        key = (flow.client_host_id, flow.server_host_id, f"{flow.protocol}/{flow.port}")
        if key in seen_edges:
            continue
        seen_edges.add(key)

        client = hosts_by_id.get(flow.client_host_id)
        client_label = client.hostname if client else flow.client_address or "external"
        cls = flow.classification.value
        color = {"preferred": "#2e7d32", "risky": "#f9a825", "unsafe": "#c62828"}.get(
            cls, "#757575"
        )
        edge_label = f"{flow.protocol}/{flow.port}\\n{flow.service_name}"
        lines.append(
            f'  "{flow.client_host_id}" -> "{flow.server_host_id}" '
            f'[label="{edge_label}", color="{color}", fontcolor="{color}"];'
        )
        if flow.client_host_id not in hosts_by_id and flow.client_address:
            ext_id = f"ext_{flow.client_address}"
            if ext_id not in [l for l in lines if ext_id in l]:
                lines.append(
                    f'  "{ext_id}" [label="{client_label}\\n(external)", '
                    f'shape=ellipse, fillcolor="#eeeeee"];'
                )

    if not seen_edges:
        for flow in ctx.flows:
            if flow.flow_kind != "listener":
                continue
            lines.extend([
                f'  subgraph cluster_{flow.server_host_id} {{',
                f'    label="listener {flow.protocol}/{flow.port}";',
                "  }",
            ])

    lines.append("}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
