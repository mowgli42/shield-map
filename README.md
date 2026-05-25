# Firewall Ruleset & Network Exposure Audit Tool

Python CLI for personal/home lab use: ingest netstat or open-port exports, classify exposure using cybersecurity best practices, generate deny-by-default firewall rules for Windows and Linux, and produce **XML audit reports** with an **XSLT** HTML view for security assessments.

## Status

**Phase 1 (MVP)** — parsers, classification, XML report, XSLT, Windows + nftables generators.

See [docs/PLAN.md](docs/PLAN.md) for the full roadmap (Phases 2–4).

## Quick start

```bash
pip install -e ".[dev]"

# Collect on each machine
netstat -ano > imports/pc/netstat.txt
ss -tulpn > imports/nas/ss.txt

# Run (rules + XML + HTML if xsltproc is installed)
fw-audit all-in-one imports/ -o out/ --hosts examples/home-lab/hosts.yaml

# Review
firefox out/audit-report.html
```

## Commands

| Command | Description |
|---------|-------------|
| `fw-audit ingest <path>` | Validate and summarize inputs |
| `fw-audit analyze <path>` | Classify ports and print findings |
| `fw-audit report <path> -o out/` | XML audit report only |
| `fw-audit generate <path> -o out/` | Firewall rulesets |
| `fw-audit all-in-one <path> -o out/` | Rules + XML + HTML |
| `fw-audit html audit-report.xml` | Transform XML to HTML |

## Documentation

- [docs/PLAN.md](docs/PLAN.md) — architecture, phases, port categories, XML/XSLT design
- [docs/compliance-mapping.md](docs/compliance-mapping.md) — CIS Controls v8.1 and NIST 800-53 / FedRAMP field mapping
- [docs/schema/network-audit.xsd](docs/schema/network-audit.xsd) — audit report schema

## Alignment

- **SANS / CIS Controls v8.1** — Implementation Group 1 (essential cyber hygiene): firewalls, port limitation, default-deny
- **FedRAMP / NIST SP 800-53 Rev 5** — SC-7 boundary protection, SC-7(5) deny-by-default, AC-4 flow documentation

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Phase 1a — Secure initial config wizard

Generate a **deny-by-default** baseline before you have netstat exports:

```bash
# Interactive (client, server, services, management CIDR)
fw-audit init -o out-init/

# Non-interactive answers file
fw-audit init --answers examples/home-lab/init-answers-server.yaml -o out-init/
```

**Questions covered:** client vs server, OS (Windows/Linux), zone, management network CIDR, optional RDP (clients), server services (file share, web, SSH, databases, NAS, VPN, etc.), HTTPS-only vs HTTP+HTTPS.

**Outputs:** `init-profile.yaml`, firewall rules with **source restrictions** (mgmt CIDR), XML audit report, `INIT-README.txt`.

| Host type | Default inbound |
|-----------|-----------------|
| Client | Deny all (optional RDP from mgmt CIDR only) |
| Server | Only selected services; SSH/SMB restricted to mgmt CIDR |
