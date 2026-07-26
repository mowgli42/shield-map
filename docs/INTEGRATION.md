# Integration contract — SnarkSentinel / library consumers

`fw-audit` exposes a small, stable Python API so local agents can review
posture, detect drift, and stage a local-only firewall profile **without**
scraping CLI stdout.

Install the package (editable or from the repo), then import from the top level:

```python
from fw_audit import analyze, diff, generate_local_only
```

Or import explicitly from `fw_audit.api` (same symbols).

## 1. Analyze current listeners

```python
from pathlib import Path
from fw_audit import analyze

result = analyze(
    Path("imports/ss.txt"),          # file or directory of netstat/ss exports
    hosts_file=Path("hosts.yaml"),   # optional
    policy_file=Path("policy.yaml"), # optional
)

print(result.summary)          # classification counts
print(result.to_dict())        # JSON-serializable posture
for finding in result.findings:
    print(finding.code, finding.severity, finding.message)
```

`analyze` is in-memory: it does **not** write rulesets or XML.

## 2. Diff against a baseline

```python
from fw_audit import analyze, diff, load_audit_xml

baseline = load_audit_xml(Path("baseline/audit-report.xml"))
current = analyze(Path("imports/live/"))

report = diff(baseline, current)
if report.has_drift:
    for change in report.changes:
        # change.kind: added | removed | changed
        # change.subject: listener | finding
        print(change.to_dict())
```

`diff` accepts any mix of:

- `AnalyzeResult` (from `analyze`)
- `AuditContext` (from `fw_audit.pipeline.run_audit` / `collect_audit`)
- path to `audit-report.xml`

Output is machine-parseable via `DiffResult.to_dict()`.

## 3. Generate a local-only ruleset profile

Intended for local agent testing: **loopback allowed**, **guardian Unix socket
documented as allowed**, **remote inbound denied**.

```python
from fw_audit import generate_local_only

profile = generate_local_only(
    Path("out-local/"),
    hostname="agent-host",
    os_family="linux",
    guardian_socket="/run/guardian.sock",  # default
)

print(profile.profile_path)     # local-only-profile.yaml
print(profile.audit_xml_path)   # audit-report.xml
for ruleset in profile.rulesets:
    print(ruleset.path)         # e.g. rules-nftables.conf
```

Notes:

- Host netfilter does not filter Unix domain sockets; the profile records the
  guardian socket path and relies on socket permissions for IPC isolation.
- Generated nftables/Windows rules use default-deny inbound with loopback
  accept and **no** non-loopback allow rules.

## Stability

| Symbol | Stability |
|--------|-----------|
| `analyze`, `diff`, `generate_local_only`, `load_audit_xml` | Supported |
| Result dataclasses + `.to_dict()` | Supported |
| `fw_audit.cli` Typer commands | CLI contract (unchanged) |
| Internal modules (`parsers`, `classify`, …) | May change without notice |

Prefer this module over parsing `fw-audit analyze --format json` stdout when
embedding in another local service.
