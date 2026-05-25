# Compliance Field Dictionary

Maps `fw-audit` XML elements and CLI behaviors to audit frameworks. Use this when writing SSP appendices or CIS self-assessment worksheets.

## XML `ComplianceMapping` block

| XML path | Framework | ID | Tool behavior |
|----------|-----------|-----|---------------|
| `/NetworkAuditReport/ComplianceMapping/Safeguard[@id='4.4']` | CIS 8.1 | 4.4 | Server firewall rules in `RulesetArtifacts` |
| `.../Safeguard[@id='4.5']` | CIS 8.1 | 4.5 | Workstation firewall rules |
| `.../Safeguard[@id='9.2']` | CIS 8.1 | 9.2 | Diff listeners vs `PolicyVersion` |
| `.../Safeguard[@id='9.4']` | CIS 8.1 | 9.4 | `default_deny=true` on host rulesets |
| `.../Safeguard[@id='12.4']` | CIS 8.1 | 12.4 | `classification=unsafe` findings |
| `.../Control[@id='SC-7']` | NIST 800-53 | SC-7 | Zone tags on hosts and flows |
| `.../Control[@id='SC-7(5)']` | NIST 800-53 | SC-7(5) | Deny-by-default rule ordering |
| `.../Control[@id='SC-7(12)']` | NIST 800-53 | SC-7(12) | Host-based generator outputs |
| `.../Control[@id='AC-4']` | NIST 800-53 | AC-4 | `Flows/Flow` matrix |
| `.../Control[@id='CM-6']` | NIST 800-53 | CM-6 | `Metadata/PolicyVersion` + checksum |

## Finding codes → remediation narrative

| Code | Severity | CIS / NIST tie-in |
|------|----------|-------------------|
| `UNSAFE_PORT_LISTENING` | critical | 12.4, SC-7(5) |
| `RISKY_PORT_PUBLIC_BIND` | high | 9.2, SC-7(b) public separation |
| `CROSS_ZONE_UNRESTRICTED` | medium | 13.3, AC-4 |
| `UNKNOWN_PORT` | low | 9.2 — review and reclassify |
| `NO_DEFAULT_DENY` | high | 9.4, SC-7(5) — generator misconfiguration |

## Status values

- `addressed` — finding absent or fully mitigated in proposed rules
- `partial` — rules proposed; not yet applied (operational gap)
- `not_applicable` — host role excludes control (document `justification`)
