# Spamhaus DROP (shield-up optional stage)

Optional **`drop`** stage in `shield-up`: load [Spamhaus DROP](https://www.spamhaus.org/drop/)
into nftables and refresh it daily.

## Why DROP

| Property | Value |
|----------|--------|
| Size | Small (~1k IPv4 netblocks; IPv6 companion list) |
| Churn | Slow-changing |
| False positives | Low (hijacked / unused space used by spam/malware) |
| Fetch policy | At most once per hour (script-enforced); cron daily is enough |

Feeds:

- IPv4: https://www.spamhaus.org/drop/drop.txt
- IPv6: https://www.spamhaus.org/drop/dropv6.txt

Format: `CIDR ; SBL…` (`;` starts a comment).

## Usage

```bash
# Generate scripts only (default)
./shield-up -o out-harden/

# Apply with prompts (includes DROP Y/n)
sudo ./shield-up --apply -o out-harden/

# Non-interactive
sudo ./shield-up --apply -y --drop -o out-harden/
sudo ./shield-up --apply -y --no-drop -o out-harden/   # skip DROP
```

Scripts:

| Script | Role |
|--------|------|
| `harden-scripts/shield-drop-refresh.sh` | Download → parse → load nftables (cron-safe) |
| `harden-scripts/07-setup-drop.sh` | Install refresh to `/usr/local/sbin/`, daily cron, initial load |

## nftables

Dedicated table (priority **-10**, before host `fw_audit` rules):

```text
table inet shield_drop {
  set shield_drop4 { type ipv4_addr; flags interval; … }
  set shield_drop6 { type ipv6_addr; flags interval; … }
  chain input  { … ip saddr @shield_drop4 drop; ip6 saddr @shield_drop6 drop; }
  chain output { … ip daddr @shield_drop4 drop; ip6 daddr @shield_drop6 drop; }
}
```

Host `rules-nftables.conf` starts with `flush ruleset`. After firewall apply,
`02-apply-firewall.sh` re-runs `shield-drop-refresh.sh` if installed so DROP
survives a flush.

## Failure behavior

- Download or parse failure → **keep previous** CIDR files and nft sets; log and exit non-zero.
- Never flush DROP sets when the new list is empty/missing.
- Failed `nft -f` → restore last-known-good `shield-drop.nft` fragment when present.
- Rate limit: skip network fetch if last **successful fetch** was &lt; 1 hour ago (re-apply only).

## State / logs

| Path | Role |
|------|------|
| `/var/lib/shield-map/drop/drop4.cidrs` | Parsed IPv4 CIDRs |
| `/var/lib/shield-map/drop/dropv6.cidrs` | Parsed IPv6 CIDRs |
| `/var/lib/shield-map/drop/shield-drop.nft` | Last applied fragment |
| `/var/lib/shield-map/drop/last-success` | Rate-limit stamp (fetch success) |
| `/etc/cron.d/shield-drop` | `30 3 * * *` daily refresh |
| `/var/log/shield-drop.log` | Cron log |
