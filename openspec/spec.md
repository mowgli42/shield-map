# OpenSpec — fw-audit (shield-map)

Living description of **shipped** architecture and capabilities.
Roadmap detail stays in [docs/PLAN.md](../docs/PLAN.md); items below marked **Planned** are not implemented.

## 1. Purpose

`fw-audit` is a Python CLI / library for home-lab firewall planning:

1. Ingest netstat / `ss` / port-list exports (or an init questionnaire).
2. Classify listeners (preferred / risky / unsafe) and multi-host flows.
3. Emit deny-by-default rulesets and audit artifacts for review-before-apply.

Stack exception vs Repo Health default (Svelte + FastAPI + SQLite/Redis): this project is a **local CLI + library** only — no web UI or server runtime.

## 2. Architecture (current)

```text
inputs (init answers | netstat/ss/port-list | hosts.yaml | policy.yaml)
        │
        ▼
   parsers → classification → flow graph → cross-zone findings
        │                         │
        ├─► generators (rules / Fail2ban / OpenCanary)
        └─► reports (XML, ports-protocols matrix, DOT) → optional XSLT HTML
```

Primary modules under `src/fw_audit/`:

| Area | Path |
|------|------|
| CLI | `cli.py` (Typer) |
| Library API | `api.py` (re-exported from `fw_audit`) |
| Orchestration | `pipeline.py`, `init/` |
| Parsers | `parsers/` |
| Classification | `classify/` |
| Multi-host graph | `graph/` |
| Generators | `generators/` |
| Reports / diff | `report/`, `diff/` |
| Policy / inventory | `policy/`, `models.py` |

## 3. Capabilities (shipped)

### 3.1 Parsers

Auto-detect via `parsers/detector.py`:

| Parser | Input |
|--------|--------|
| `netstat_windows` | Windows `netstat -ano` style |
| `netstat_linux` | Linux `netstat` active internet connections |
| `ss_linux` | Linux `ss -tulpn` (and similar) |
| `port_list` | Simple CSV / port list |

Listeners and TCP sessions (where present) feed the graph.

### 3.2 Classification

- Policy from packaged `classify/defaults.yaml` and optional `policy.yaml`.
- Categories: **preferred**, **risky**, **unsafe** (plus unknown).
- Findings attached to listeners; used by generators and reports.

### 3.3 Multi-host graph

- `hosts.yaml` inventory (zones, roles, IPs, `allowed_zone_pairs`).
- Batch ingest of per-host export directories.
- Flow graph from listeners + ESTABLISHED sessions (`graph/flows.py`).
- Cross-zone findings (`graph/cross_zone.py`).
- Optional Graphviz DOT (`report/dot_export.py` → `network-dataflow.dot`).

### 3.4 Generators

Emitted under `out/<hostname>/` when `generate` / `all-in-one` runs (and hosts have listeners):

| Artifact | Platform flag / trigger |
|----------|-------------------------|
| `rules-windows.ps1` | `windows` / `all` |
| `rules-nftables.conf` | `nftables` / `linux` / `all` |
| `rules-cisco-ios.acl` | `cisco` / `all` |
| `jail.d/fw-audit.conf` (Fail2ban) | `fail2ban`, or with `nftables` / `all` |
| `.opencanary.conf` + `opencanary-ports.json` | Always when generate path runs for a host with listeners |

OpenCanary output is deception **suggestions**, not a firewall ruleset.

### 3.5 Reports

| Output | How |
|--------|-----|
| `audit-report.xml` | `report` / `all-in-one` / `init` / library |
| XSD | `docs/schema/network-audit.xsd` |
| `audit-report.html` | `fw-audit html` or `all-in-one` when `xsltproc` is installed |
| `ports-protocols.json` (+ YAML/CSV sidecars) | `report` / `all-in-one` |
| `network-dataflow.dot` | `all-in-one` (`--dot` / `--no-dot`) |

### 3.6 Diff

- CLI: `fw-audit diff <baseline.xml> <current.xml>` (`--format text|json`, exit 1 on drift).
- Library: `fw_audit.diff` / `api.diff` — listener and finding added/removed/changed.

### 3.7 Init (Phase 1a)

- `fw-audit init` interactive wizard or `--answers` YAML / `--non-interactive`.
- Writes `init-profile.yaml`, rulesets, XML, `INIT-README.txt`.

### 3.8 CLI surface

| Command | Role |
|---------|------|
| `version` | Package version |
| `init` | Secure baseline from questionnaire |
| `ingest` | Validate inputs (listeners + sessions) |
| `analyze` | Classify + findings (`text` / `json`) |
| `report` | XML + ports/protocols matrix |
| `generate` | Rulesets / Fail2ban / OpenCanary |
| `all-in-one` | Rules + XML + matrix + DOT (+ HTML if possible) |
| `html` | XSLT transform (requires `xsltproc`) |
| `diff` | Drift vs baseline XML |

### 3.9 Library API

Supported import surface (`docs/INTEGRATION.md`):

```python
from fw_audit import analyze, diff, generate_local_only, load_audit_xml
```

| Symbol | Behavior |
|--------|----------|
| `analyze` | In-memory posture from exports (no artifact writes) |
| `diff` | Drift between analyze results / contexts / XML paths |
| `generate_local_only` | Loopback-allowed, remote-inbound-denied profile for agent testing |
| `load_audit_xml` | Load listeners/findings from `audit-report.xml` |

Internal packages may change without notice; prefer this surface over scraping CLI stdout.

## 4. Planned (not shipped)

Keep these out of “current capability” claims until implemented:

- Cloud artifact generators (AWS / Azure / GCP) — Phase 3
- Approved source CIDRs for risky ports; compliance auto-section in XML
- Optional nmap XML import
- `fw-audit policy validate` (policy lint)
- Pre-commit hook example for exported reports

See phase tables in README and [docs/PLAN.md](../docs/PLAN.md).

## 5. Verification map

| Claim | Check against |
|-------|----------------|
| Parsers | `src/fw_audit/parsers/`, `tests/test_parsers.py` |
| Classification | `src/fw_audit/classify/`, `tests/test_classify.py` |
| Multi-host / graph | `src/fw_audit/graph/`, `tests/test_phase2.py` |
| Generators | `src/fw_audit/generators/`, Fail2ban/OpenCanary tests |
| Reports / matrix | `src/fw_audit/report/`, `tests/test_ports_protocols.py` |
| Diff | `src/fw_audit/diff/`, `tests/test_diff.py` |
| Library API | `src/fw_audit/api.py`, `tests/test_api.py` |
| Init | `src/fw_audit/init/`, `tests/test_init.py` |

Smoke: `pytest -q` from a venv with `pip install -e ".[dev]"`.
