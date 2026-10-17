# Migration: `fw-audit` → `shield-map` / `shield-up` / `shield-audit`

## What changed

| Before | After (canonical) |
|--------|-------------------|
| `fw-audit all-in-one` / live capture | **`shield-map`** |
| `fw-audit harden` | **`shield-up`** |
| Cron drift / `fw-audit diff` | **`shield-audit`** |
| `jail.d/fw-audit.conf` | `jail.d/shield-map.conf` |
| `/var/lib/fw-audit/` | `/var/lib/shield-map/` |
| `/etc/cron.d/fw-audit-drift` | `/etc/cron.d/shield-audit` |

The **Python package import path remains `fw_audit`** for this release so SnarkSentinel and other embedders do not need to change imports. The legacy `fw-audit` console script still works and prints a short deprecation note.

**Pip distribution name** is still `fw-audit` (product CLIs are `shield-map` / `shield-up` / `shield-audit`). Recommended install:

```bash
pip install "fw-audit @ git+https://github.com/mowgli42/shield-map.git"
```

A pip project rename/alias to `shield-map` (keeping `import fw_audit`) is a tracked follow-up — not in this release.

**Library DiffResult:** `from fw_audit import diff` returns `has_drift` / `changes`. XML CLI diff returns `drift_detected` / `findings`. Both types expose the other names as aliases (see [INTEGRATION.md](INTEGRATION.md)).

**Automation:** `shield-up` defaults to scripts-only (no apply). `--scripts-only` / `--apply` are a **stable** contract; any rename will be documented here.

## Install

```bash
git clone <repo> && cd shield-map
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# From the repo (wrappers bootstrap the venv if needed)
./shield-map --help
./shield-up --help
./shield-audit --help

# Or use pip-installed entry points on PATH
.venv/bin/shield-map --version
```

Optional: `sudo ln -s "$(pwd)/shield-map" /usr/local/bin/shield-map` (and same for `shield-up`, `shield-audit`). Keep `_shield_lib.sh` next to the scripts, or rely on the pip entry points instead.

---

## shield-up

**What it does:** One-shot Linux harden composition:

1. discover open ports → 2. generate nftables / Fail2ban / OpenCanary artifacts →  
3. apply firewall → 4. Fail2ban → 5. optional OpenCanary (Y/n) →  
6. optional filtered DNS `1.1.1.2` + `9.9.9.9` (Y/n) →  
7. optional Spamhaus DROP (Y/n; nftables + daily refresh) →  
8. install **`shield-audit`** cron.

Distro detection at startup (Red Hat / Ubuntu / Arch·Omarchy) writes tailored scripts under `<out>/harden-scripts/`.

**How to integrate**

```bash
# Review only (default)
./shield-up -o out-harden/

# Apply interactively
sudo ./shield-up --apply -o out-harden/

# Non-interactive (Ansible / cloud-init / bootstrap)
sudo ./shield-up --apply -y --opencanary --dns --drop -o /var/lib/shield-map/bootstrap/
```

**Artifacts / logs**

| Path | Role |
|------|------|
| `out-harden/audit-report.xml` | Baseline for drift |
| `out-harden/<host>/rules-nftables.conf` | Host firewall |
| `out-harden/<host>/jail.d/shield-map.conf` | Fail2ban drop-in |
| `out-harden/harden-scripts/` | Distro-specific apply scripts |
| `out-harden/harden-scripts/07-setup-drop.sh` | Spamhaus DROP install + cron |
| `out-harden/harden-scripts/shield-drop-refresh.sh` | Cron-safe DROP refresh |
| `/var/lib/shield-map/drop/` | DROP CIDR lists + last-good nft fragment |
| `/var/log/shield-audit.log` | Cron drift log (after apply) |
| `/var/log/shield-drop.log` | DROP refresh log (after apply) |
| `journalctl -u fail2ban` / `opencanary` | Service health |

Operator notes for DROP size, rate limits, and failure behavior: [SPAMHAUS-DROP.md](SPAMHAUS-DROP.md).

---

## shield-audit

**What it does:** Capture current listeners (or `--input`), write a fresh report, **diff** against the baseline XML. Exit **1** on drift, **2** on usage/IO errors, **0** when clean.

**How to integrate**

- Installed by `shield-up` stage 8 as `/etc/cron.d/shield-audit` → `/usr/local/sbin/shield-audit-cron.sh`
- Manual: `./shield-audit -b out-harden/audit-report.xml -o /tmp/drift-check`
- systemd timer or external scheduler can call the same binary

**Artifacts**

| Path | Role |
|------|------|
| `<out>/audit-report.xml` | Current posture |
| `<out>/drift-summary.txt` | Human/machine-readable diff |
| `/var/lib/shield-map/baseline-audit-report.xml` | Default baseline after shield-up |

Legacy baseline path `/var/lib/fw-audit/baseline-audit-report.xml` is still accepted if the new path is missing.

---

## Troubleshooting

| Symptom | Where to look | Fix |
|---------|---------------|-----|
| `nft: command not found` | `harden-scripts/01-install-deps.sh` | Install nftables package for your distro; prefer nftables over legacy iptables-only hosts |
| Fail2ban jail disabled | `jail.d/shield-map.conf` comments | Add a matching `filter.d` or enable only stock filters (sshd, etc.) |
| OpenCanary port conflict | `.opencanary.conf`, `ss -tulpn` | Disable modules for ports already in use; re-run configure |
| DNS not applied | `05-setup-dns.sh`, `resolvectl status` | Confirm systemd-resolved or NetworkManager path; avoid DHCP overwrite of `/etc/resolv.conf` |
| DROP not refreshing | `/var/log/shield-drop.log`, `nft list table inet shield_drop` | Check curl/wget, rate-limit stamp, and that download failures keep prior sets by design |
| Unsupported distro | Startup banner `family=unknown` | Install nftables/fail2ban manually; run generated scripts after edit |
| Missing baseline | `shield-audit` exit 2 | Pass `-b` or run `shield-up` first |
| Permission denied on `ss`/`nft` | stderr | Re-run apply stages with sudo |
| Drift false positives | `drift-summary.txt` | Refresh baseline after intentional changes: copy new `audit-report.xml` to baseline path |

**Look first:** `harden-scripts/README.txt`, `audit-report.xml`, then system logs (`journalctl`, Fail2ban log, `/var/log/shield-audit.log`).
