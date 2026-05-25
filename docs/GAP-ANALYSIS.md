# Gap Analysis — fw-audit vs GitHub Firewall / Network Security Tools

Research date: 2026. Comparison against open-source tools to inform Phase 3–4 roadmap.

## Tools reviewed

| Project | Focus | Stars (approx.) | Relevance |
|---------|--------|-----------------|------------|
| [SyntaxDiffusion/GATEKEEP](https://github.com/SyntaxDiffusion/GATEKEEP) | Home LAN scan, AI reports, firewall advisor | New | Closest “home user” competitor; live discovery + AI |
| [msaadshabir/net-guardian](https://github.com/msaadshabir/net-guardian) | ARP + Nmap audit, ML anomalies, risky ports | Small | Active scanning + historical diff |
| [StasX-Official/xnet](https://github.com/StasX-Official/xnet) | CLI port scan, packet craft, knock | Small | Scanner toolkit, not rules-as-audit-artifact |
| [fwbuilder/fwbuilder](https://github.com/fwbuilder/fwbuilder) | GUI multi-platform policy compiler | ~300 | Mature Cisco/iptables generation; GUI-first |
| [Linuxfabrik/firewallfabrik](https://github.com/Linuxfabrik/firewallfabrik) | fwbuilder successor, Qt, nftables | ~16 | Central policy DB, enterprise scale |
| [gcoffey/ansible-fwbuilder](https://github.com/gcoffey/ansible-fwbuilder) | Ansible → iptables | 1 | IaC deploy pattern |
| [Aerleon](https://github.com/aerleon) (ecosystem) | YAML ACL → multi-vendor | Active | Rule shadowing, ASA/Cisco depth |
| IPparse template builder | CSV → iptables/nftables/AWS | Web | Policy-as-CSV single source of truth |

## fw-audit differentiators (today)

- **Offline / air-gap friendly** — netstat exports only; no live scan required
- **Audit XML + XSD + XSLT** — GRC-friendly evidence (CIS / NIST mapping)
- **Phase 1a init wizard** — secure baseline without prior inventory
- **Phase 2** — multi-host zone graph, cross-zone findings, Cisco ACL, Graphviz DOT
- **Deny-by-default** aligned to CIS 9.4 / SC-7(5)

## Gaps to address (prioritized)

### High (home-lab value)

| Gap | Seen in | Recommendation |
|-----|---------|----------------|
| **Live discovery** | GATEKEEP, net-guardian | Optional nmap/ARP ingest (Phase 4) |
| **Scan vs baseline diff** | GATEKEEP baselines, net-guardian history | `fw-audit diff` on two XML reports (Phase 4) |
| **AWS/Azure/GCP rules** | IPparse, Aerleon | Phase 3 cloud generators |
| **Rule shadowing / duplicate detection** | Aerleon, fwbuilder | Lint module on generated ACLs |
| **Deploy / rollback** | fwbuilder SSH deploy | Out of scope; document “review then apply” only |

### Medium

| Gap | Seen in | Recommendation |
|-----|---------|----------------|
| **GUI policy editor** | fwbuilder, FirewallFabrik | Stay CLI; optional web viewer for XML/HTML |
| **AI narrative report** | GATEKEEP | Optional; not core—XML is source of truth |
| **CVE / service version** | net-guardian, xnet | Correlate port + banner (needs scan input) |
| **Ansible/Terraform export** | ansible-fwbuilder | `fw-audit export ansible` template (Phase 4) |
| **pfSense/OPNsense** | fwbuilder | Additional generator target |

### Low / intentional omissions

| Gap | Rationale |
|-----|-----------|
| Real-time packet monitor | Home tool; complexity vs value |
| Router CGI integration | Vendor-specific; fragile |
| Auto-apply rules | Safety risk for personal use |

## Positioning statement

**fw-audit** is not a replacement for Firewall Builder or GATEKEEP. It is an **evidence-first, offline audit and ruleset drafting tool** for home labs and small networks where you already have netstat exports or a defined architecture (init wizard), and you need CIS/FedRAMP-aligned documentation of ports, zones, and flows.
