"""Interactive questionnaire for secure initial firewall configuration."""

from __future__ import annotations

from pathlib import Path

import typer

from fw_audit.init.profile import HostIntent, load_services_catalog


def _prompt_choice(label: str, options: list[str], default: int = 0) -> str:
    typer.echo(f"\n{label}")
    for i, opt in enumerate(options, start=1):
        mark = " (default)" if i - 1 == default else ""
        typer.echo(f"  {i}) {opt}{mark}")
    raw = typer.prompt("Choice", default=str(default + 1))
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(options):
            return options[idx]
    except ValueError:
        pass
    return options[default]


def _prompt_services(host_type: str) -> list[str]:
    catalog = load_services_catalog()
    defs = catalog.get("services", {})
    roles_ok = {"server", "both"}
    if host_type not in roles_ok:
        return []

    available: list[tuple[str, str]] = []
    for sid, svc in defs.items():
        svc_roles = svc.get("roles", ["server", "both"])
        if not any(r in (host_type, "both", "server") for r in svc_roles):
            continue
        available.append((sid, svc.get("label", sid)))

    typer.echo("\nServer services (comma-separated numbers, or 'none'):")
    for i, (sid, label) in enumerate(available, start=1):
        typer.echo(f"  {i}) {label} [{sid}]")

    raw = typer.prompt("Select services", default="1").strip().lower()
    if raw in ("none", "", "0"):
        return []

    selected: list[str] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            idx = int(part) - 1
            if 0 <= idx < len(available):
                selected.append(available[idx][0])
        except ValueError:
            if part in defs:
                selected.append(part)

    if host_type in roles_ok and "ssh" not in selected:
        if typer.confirm("Include SSH administration from management network?", default=True):
            selected.insert(0, "ssh")

    return list(dict.fromkeys(selected))


def run_wizard() -> HostIntent:
    typer.echo("=== fw-audit secure initial firewall wizard (Phase 1a) ===")
    typer.echo("Answer a few questions to generate a deny-by-default ruleset.\n")

    hostname = typer.prompt("Hostname", default="homelab-host")
    host_type = _prompt_choice(
        "What is this machine primarily?",
        ["client", "server", "both"],
        default=0,
    )
    os_family = _prompt_choice("Operating system", ["linux", "windows"], default=0)
    zone = _prompt_choice(
        "Network zone",
        ["internal", "dmz", "mgmt", "public"],
        default=0,
    )
    mgmt_cidr = typer.prompt(
        "Management network CIDR (sources allowed for SSH/RDP/SMB)",
        default="192.168.0.0/16",
    )

    allow_rdp = False
    services: list[str] = []
    web_mode = "https-only"
    internet_facing = zone in ("dmz", "public")

    if host_type in ("client", "both"):
        allow_rdp = typer.confirm(
            "Allow Remote Desktop (RDP) inbound from management network only?",
            default=False,
        )

    if host_type in ("server", "both"):
        services = _prompt_services(host_type)
        if "web" in services:
            if typer.confirm("Allow plain HTTP (port 80) in addition to HTTPS?", default=False):
                web_mode = "http-and-https"
            else:
                web_mode = "https-only"
                typer.echo("  → HTTPS only (port 443); port 80 will not be opened.")

    if zone not in ("dmz", "public"):
        internet_facing = typer.confirm(
            "Is this host directly internet-facing (public IP)?",
            default=False,
        )

    outbound = True
    if host_type in ("client", "both"):
        outbound = typer.confirm(
            "Document client outbound allowances (DNS, HTTPS) in Linux rules?",
            default=True,
        )

    intent = HostIntent(
        hostname=hostname,
        host_type=host_type,
        os_family=os_family,
        zone=zone,
        mgmt_cidr=mgmt_cidr,
        services=services,
        allow_rdp=allow_rdp,
        web_mode=web_mode,
        internet_facing=internet_facing,
        allow_outbound_dns_https=outbound,
    )

    typer.echo("\n--- Planned configuration ---")
    typer.echo(f"  Host: {intent.hostname} ({intent.host_type}, {intent.os_family})")
    typer.echo(f"  Zone: {intent.zone} | Mgmt CIDR: {intent.mgmt_cidr}")
    if intent.allow_rdp:
        typer.echo("  Client: RDP from mgmt network only")
    if intent.services:
        typer.echo(f"  Services: {', '.join(intent.services)}")
    if host_type in ("client", "both") and not intent.allow_rdp and not intent.services:
        typer.echo("  Inbound: default deny only (recommended for clients)")
    typer.echo("")

    return intent


def load_or_wizard(answers: Path | None, non_interactive: bool) -> HostIntent:
    if answers:
        from fw_audit.init.profile import load_intent

        return load_intent(answers)
    if non_interactive:
        typer.echo("Provide --answers <file.yaml> for non-interactive mode.", err=True)
        raise typer.Exit(1)
    return run_wizard()
