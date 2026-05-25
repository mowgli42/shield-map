# Firewall Ruleset & Network Exposure Audit Tool

Python CLI (planned) for personal/home lab use: ingest netstat or open-port exports, classify exposure using cybersecurity best practices, generate deny-by-default firewall rules for Windows, Linux, Cisco, and cloud platforms, and produce **XML audit reports** with an **XSLT** HTML view for security assessments.

## Status

Repository planning phase. See the implementation plan:

- [docs/PLAN.md](docs/PLAN.md) — architecture, phases, port categories, XML/XSLT design
- [docs/compliance-mapping.md](docs/compliance-mapping.md) — CIS Controls v8.1 and NIST 800-53 / FedRAMP field mapping

## Alignment

- **SANS / CIS Controls v8.1** — Implementation Group 1 (essential cyber hygiene): firewalls, port limitation, default-deny
- **FedRAMP / NIST SP 800-53 Rev 5** — SC-7 boundary protection, SC-7(5) deny-by-default, AC-4 flow documentation

## License

Apache License 2.0 — see [LICENSE](LICENSE).
