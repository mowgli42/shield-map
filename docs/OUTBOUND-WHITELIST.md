# Outbound whitelisting and host network profile

## Does fw-audit enforce “trusted apps only” for internet access?

**Partially — by design for home lab use.**

| Layer | Supported today | Notes |
|-------|-----------------|-------|
| **Port/protocol egress whitelist** | Yes (Linux nftables) | `outbound_whitelist.enforce: true` → default-deny **output** chain; allow DNS/HTTPS/etc. from policy |
| **Process name audit** | Yes (Linux `ss -tulpn`) | Report lists which process reaches which internet destination |
| **Windows per-application block** | Limited | Generated rules are port-based; **true app whitelist** needs [WDAC](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control-wdac) or AppLocker |
| **Live enforcement daemon** | No | Tool generates **review-then-apply** configs; does not install a persistent agent |

fw-audit is an **audit + ruleset drafting** tool aligned with CIS 9.4 / SC-7(5), not a full endpoint DLP product.

## Enable outbound whitelist

```yaml
# policy.yaml
outbound_whitelist:
  enforce: true
  trusted_gateways:
    - "192.168.1.1"
  trusted_dns:
    - "192.168.1.1"
    - "1.1.1.1"
  approved_outbound_ports:
    - { proto: udp, port: 53, service: dns }
    - { proto: tcp, port: 443, service: https }
  approved_processes:
    - firefox
    - systemd-resolved
  client_interface_policy:
    wifi_allowed: false
    bluetooth_allowed: false
```

```bash
fw-audit all-in-one imports/ --hosts hosts.yaml --policy policy.yaml -o out/
```

Findings include `UNAPPROVED_OUTBOUND`, `UNTRUSTED_DNS`, `WIFI_INTERFACE_UP`, etc.

## Collect gateway, DNS, and NIC data

Per host, add a profile export beside netstat:

**Windows**

```cmd
ipconfig /all > imports\pc01\ipconfig.txt
netstat -ano > imports\pc01\netstat.txt
```

**Linux**

```bash
{
  echo "# ip-route"
  ip route
  echo "# resolv.conf"
  cat /etc/resolv.conf
  echo "# ip-link"
  ip link
} > imports/pc01/network-linux.txt
ss -tulpn > imports/pc01/ss.txt
```

Or use: `bash scripts/collect-linux.sh > imports/pc01/network-linux.txt`

## XML report sections

- **HostNetworkProfiles** — default gateway, DNS servers, each NIC (ethernet / wifi / bluetooth / virtual), up/down
- **OutboundClientServices** — process, remote IP:port, classification, `approved=true|false`

## What we cannot infer from netstat alone

- Application identity on Windows without `netstat -b` (admin) or ETW
- VPN split-tunnel paths without `ip route` export
- Bluetooth PAN routing without `ip link` / `rfkill`

Always ship **network profile** exports with netstat for complete client reports.
