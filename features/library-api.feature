Feature: Library API analyze and generate_local_only
  Stable Python contract for SnarkSentinel / embedders — analyze posture
  in-memory and draft a local-only ruleset profile without scraping CLI
  stdout. Aligns with `fw_audit.api` and `docs/INTEGRATION.md`.
  Covered by `tests/test_api.py`.

  Scenario: analyze returns structured listeners without writing artifacts
    Given fixture export "tests/fixtures/ss-linux.txt"
    When the consumer calls `analyze(<fixture>)`
    Then the result is an AnalyzeResult with listeners including tcp/22 and tcp/80
    And `result.to_dict()` includes summary and listeners
    And no files are written under the caller's output directory

  Scenario: generate_local_only drafts loopback-only deny-by-default profile
    When the consumer calls `generate_local_only(<out>, hostname="agent01", os_family="linux")`
    Then `<out>/local-only-profile.yaml` documents remote_inbound_denied and the guardian socket
    And `<out>/audit-report.xml` is written
    And the nftables ruleset accepts loopback (`iif lo accept`) with `policy drop`
    And no non-loopback `dport` allow rules are generated
    And `profile.to_dict()` reports loopback_allowed and remote_inbound_denied

  Scenario: library diff detects an added listener against an XML baseline
    Given a baseline audit-report.xml from `run_audit` on "tests/fixtures/ss-linux.txt"
    And a current AnalyzeResult with an extra tcp/2375 listener
    When the consumer calls `diff(baseline, current)`
    Then `report.has_drift` is true
    And changes include an added listener whose key contains "2375"
