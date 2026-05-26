# Example: Simple client (Phase 1a init)

Scenario: Windows workstation on internal LAN — **no inbound services**, optional outbound documented on Linux peers.

## Command

```bash
fw-audit init --answers examples/home-lab/init-answers-client.yaml -o out-client/
```

## Answers (`init-profile.yaml`)

```yaml
hostname: homelab-pc
host_type: client
os_family: windows
zone: internal
mgmt_cidr: "192.168.1.0/24"
services: []
allow_rdp: false
```

## Generated Windows rules (excerpt)

```powershell
Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block
# No inbound allow rules — default deny only (CIS 9.4)
```

## Audit summary

| Metric | Value |
|--------|-------|
| Inbound allows | **0** |
| Findings | **0** |
| Posture | Deny-all inbound; suitable baseline before enabling RDP/file share |

To allow RDP from the management network only, re-run the wizard and answer **yes** to Remote Desktop.
