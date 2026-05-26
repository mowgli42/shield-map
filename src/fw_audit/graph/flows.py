"""Build flow records from listeners and active sessions."""

from __future__ import annotations

from fw_audit.classify.engine import ClassificationEngine
from fw_audit.graph.ipmap import resolve_host
from fw_audit.models import Classification, Connection, Flow, Host, Listener


def build_listener_flows(listeners: list[Listener], hosts: dict[str, Host]) -> list[Flow]:
    flows: list[Flow] = []
    for idx, listener in enumerate(listeners, start=1):
        host = hosts.get(listener.host_id)
        zone = host.zone if host else "internal"
        exposure = "public" if listener.bind_address in ("0.0.0.0", "::", "*") else "internal"

        flows.append(
            Flow(
                id=f"L{idx:03d}",
                server_host_id=listener.host_id,
                server_address=listener.bind_address,
                server_zone=zone,
                protocol=listener.protocol,
                port=listener.port,
                classification=listener.classification,
                service_name=listener.service_name or f"port-{listener.port}",
                direction="inbound",
                client_zone="unknown" if exposure == "public" else "internal",
                flow_kind="listener",
            )
        )
    return flows


def build_session_flows(
    connections: list[Connection],
    hosts: dict[str, Host],
    ip_map: dict[str, Host],
    engine: ClassificationEngine,
    start_id: int = 1,
) -> list[Flow]:
    flows: list[Flow] = []
    idx = start_id

    for conn in connections:
        observer = hosts.get(conn.host_id)
        if not observer:
            continue

        remote_host = resolve_host(conn.remote_address, ip_map)
        local_host = resolve_host(conn.local_address, ip_map) or observer

        # Determine server side (lower port heuristic when both known; else local if listening port match)
        if conn.local_port < conn.remote_port:
            server_port = conn.local_port
            server_addr = conn.local_address
            client_addr = conn.remote_address
            server_host = local_host
            client_host = remote_host
        else:
            server_port = conn.remote_port
            server_addr = conn.remote_address
            client_addr = conn.local_address
            server_host = remote_host
            client_host = local_host

        if server_port <= 0:
            continue

        server_hid = server_host.id if server_host else conn.host_id
        server_zone = server_host.zone if server_host else observer.zone
        client_zone = client_host.zone if client_host else "external"
        client_hid = client_host.id if client_host else None

        stub = Listener(
            host_id=server_hid,
            protocol=conn.protocol,
            port=server_port,
            bind_address=server_addr,
        )
        classification = engine.classify_listener(stub, server_host or observer)

        flows.append(
            Flow(
                id=f"S{idx:03d}",
                server_host_id=server_hid,
                server_address=server_addr,
                server_zone=server_zone,
                protocol=conn.protocol,
                port=server_port,
                classification=classification,
                service_name=stub.service_name or f"port-{server_port}",
                client_host_id=client_hid,
                client_address=client_addr,
                client_zone=client_zone,
                direction="session",
                flow_kind="session",
            )
        )
        idx += 1

    return flows


def build_flows(
    listeners: list[Listener],
    hosts: dict[str, Host],
    connections: list[Connection] | None = None,
    ip_map: dict[str, Host] | None = None,
    engine: ClassificationEngine | None = None,
) -> list[Flow]:
    by_id = {h.id: h for h in hosts.values() if h.id.startswith("H")}
    listener_flows = build_listener_flows(listeners, by_id)
    if not connections or not engine:
        return listener_flows

    session_flows = build_session_flows(
        connections,
        by_id,
        ip_map or {},
        engine,
        start_id=len(listener_flows) + 1,
    )
    return listener_flows + session_flows


def summary_counts(flows: list[Flow]) -> dict[str, int]:
    counts = {c.value: 0 for c in Classification}
    for flow in flows:
        counts[flow.classification.value] = counts.get(flow.classification.value, 0) + 1
    return counts
