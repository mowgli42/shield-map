Feature: fw-audit init baseline
  Phase 1a creates a secure firewall baseline from questionnaire answers
  (no netstat/ss export required). Aligns with `fw-audit init` and
  `fw_audit.init.pipeline.run_init`. Covered by `tests/test_init.py`.

  Scenario: Non-interactive server init writes profile, XML, and nftables
    Given answers file "examples/home-lab/init-answers-server.yaml"
    When the operator runs `fw-audit init --answers <answers> -o <out> --platform nftables --non-interactive`
    Then `<out>/init-profile.yaml` is written
    And `<out>/audit-report.xml` is written
    And `<out>/INIT-README.txt` is written
    And a deny-by-default nftables ruleset exists under `<out>/<hostname>/`
    And management CIDR restrictions appear for SSH/fileshare services
    And HTTPS is allowed while HTTP port 80 is not opened

  Scenario: Client init baseline has no planned inbound listeners
    Given a client HostIntent with no inbound services and RDP disabled
    When listeners are built from that intent
    Then there are no inbound listeners (outbound-only / empty inbound set)
    And the derived policy marks `init_baseline` as true
