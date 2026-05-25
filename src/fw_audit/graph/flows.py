"""Build flow records from classified listeners."""

from __future__ import annotations

from fw_audit.models import Classification, Flow, Host, Listener


def build_flows(listeners: list[Listener], hosts: dict[str, Host]) -> list[Flow]:
    flows: list[Flow] = []
    for idx, listener in enumerate(listeners, start=1):
        host = hosts.get(listener.host_id)
        zone = host.zone if host else "internal"
        exposure = "public" if listener.bind_address in ("0.0.0.0", "::", "*") else "internal"

        flows.append(
            Flow(
                id=f"F{idx:03d}",
                server_host_id=listener.host_id,
                server_address=listener.bind_address,
                server_zone=zone,
                protocol=listener.protocol,
                port=listener.port,
                classification=listener.classification,
                service_name=listener.service_name or f"port-{listener.port}",
                direction="inbound",
                client_zone="unknown" if exposure == "public" else "internal",
            )
        )
    return flows


def summary_counts(flows: list[Flow]) -> dict[str, int]:
    counts = {c.value: 0 for c in Classification}
    for flow in flows:
        counts[flow.classification.value] = counts.get(flow.classification.value, 0) + 1
    return counts
