# Integration contract — SnarkSentinel / library consumers

`fw_audit` exposes a small, stable Python API so local agents can review
posture, detect drift, and stage a local-only firewall profile **without**
scraping CLI stdout.

**CLI rename (user-facing):** prefer `shield-map`, `shield-up`, and `shield-audit`.
The **import package name stays `fw_audit`** this release — no code change required
for SnarkSentinel imports. See [MIGRATION.md](MIGRATION.md).

## Install (recommended one-liner)

```bash
# Product name is shield-map; pip distribution / import remain fw-audit this release
pip install "fw-audit @ git+https://github.com/mowgli42/shield-map.git"

# Verify
python -c "import fw_audit; print(fw_audit.__version__)"
shield-map --version
shield-up --version
shield-audit --version
```

Editable checkout:

```bash
pip install -e "/path/to/shield-map[dev]"
```

A future pip project rename/alias to `shield-map` is tracked as a follow-up; until then
installers should use the line above and treat console scripts as the product names.

Import from the top level (or `fw_audit.api`):

```python
from fw_audit import analyze, diff, generate_local_only
```

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

## 2. Diff against a baseline (library API)

Prefer **`from fw_audit import diff`** (returns `fw_audit.api.DiffResult`):

```python
from fw_audit import analyze, diff, load_audit_xml

baseline = load_audit_xml(Path("baseline/audit-report.xml"))
current = analyze(Path("imports/live/"))

report = diff(baseline, current)
if report.has_drift:                       # also: report.drift_detected
    for change in report.changes:          # also: report.findings
        # change.kind: added | removed | changed
        # change.subject: listener | finding
        print(change.to_dict())
```

`diff` accepts any mix of:

- `AnalyzeResult` (from `analyze`)
- `AuditContext` (from `fw_audit.pipeline.run_audit` / `collect_audit`)
- path to `audit-report.xml`

Canonical fields: **`has_drift`**, **`changes`** (`DiffChange` with `kind` / `subject`).
Compatibility aliases (same objects): **`drift_detected`**, **`findings`**.
`to_dict()` emits both key pairs.

### Do not confuse with the XML CLI DiffResult

| Import / call | Type | Drift flag | Items |
|---------------|------|------------|-------|
| `from fw_audit import diff` | `fw_audit.api.DiffResult` | `has_drift` | `changes` (`DiffChange`) |
| `fw_audit.diff.diff_paths` / `shield-audit` / `fw-audit diff` | `fw_audit.diff.compare.DiffResult` | `drift_detected` | `findings` (`DriftFinding`) |

Both types expose the **alias pair** so defensive `getattr(report, "has_drift", …)` works either way.
For in-process agents, stick to **`from fw_audit import diff`**.

For host cron / ops, prefer the **`shield-audit`** CLI (writes `drift-summary.txt`,
exit 1 on drift) rather than scraping CLI stdout from agents.

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

## 4. Embedder baseline layout (non-root agents)

Host defaults for **`shield-audit`** assume root-friendly paths under
`/var/lib/shield-map/`. Services like SnarkSentinel that run as a non-root
user should keep baselines under their own data directory.

Recommended layout:

```text
<data_dir>/shield-map/
  harden/                 # output of: shield-up --scripts-only -o …
    audit-report.xml      # optional host-style baseline from shield-up
    harden-scripts/       # review-before-apply scripts (do not auto-apply)
  baseline/
    audit-report.xml      # OR snapshot from analyze → write_audit_xml / run_audit
  current/                # optional scratch for CLI shield-audit -o …
  imports/                # live ss/netstat captures for analyze()
```

Guidance:

1. Prefer **library** `analyze` + `diff` for in-process posture (no CLI scrape).
2. Baseline may be:
   - `audit-report.xml` from `shield-up --scripts-only` / `shield-map` / `run_audit`, or
   - an `AnalyzeResult` / `AuditContext` held in memory / serialized by the agent.
3. `diff(baseline_xml_path, current_analyze_result)` is supported — mix path and
   `AnalyzeResult` freely.
4. Do **not** require `/var/lib/shield-map/` when the agent is non-root; pass
   explicit paths to `shield-audit -b … -o …` only if you also use the CLI.

## 5. Invoking user CLIs from automation

| Task | Prefer |
|------|--------|
| Rules + XML from export or live capture | `shield-map` |
| Linux harden / install Fail2ban / DNS / DROP / cron | `shield-up` |
| Drift vs stored baseline | `shield-audit` or library `diff` |

**Stable automation contract:** `shield-up` defaults to **scripts-only** (no apply).
`--scripts-only` / `--apply` are the supported flags for Ansible, cloud-init, and
SnarkSentinel install. Example:

```bash
"${VENV}/bin/shield-up" --scripts-only -o "${DATA_DIR}/shield-map/harden/"
```

If these flag names ever change, it will be called out in [MIGRATION.md](MIGRATION.md).

Fail2ban drop-in path is `jail.d/shield-map.conf` (was `fw-audit.conf`).

## Stability

| Symbol | Stability |
|--------|-----------|
| `analyze`, `diff`, `generate_local_only`, `load_audit_xml` | Supported |
| `DiffResult.has_drift` / `.changes` (and aliases `.drift_detected` / `.findings`) | Supported |
| Result dataclasses + `.to_dict()` | Supported |
| `shield-map` / `shield-up` / `shield-audit` | Supported user CLIs |
| `shield-up --scripts-only` (default non-apply) | Supported automation contract |
| `fw-audit` Typer commands | Deprecated alias (still functional) |
| Internal modules (`parsers`, `classify`, …) | May change without notice |

Prefer this module over parsing CLI stdout when embedding in another local service.
