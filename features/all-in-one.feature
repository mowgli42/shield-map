Feature: fw-audit all-in-one audit
  End-to-end audit from netstat/ss exports: classify listeners, emit
  rulesets, XML report, ports/protocols matrix, and optional DOT graph.
  Aligns with `fw-audit all-in-one` / `fw_audit.pipeline.run_audit`.
  Covered by `tests/test_pipeline.py` and `tests/test_phase2.py`.

  Scenario: Single-host fixture produces report, matrix, and rulesets
    Given fixture export "tests/fixtures/netstat-windows.txt"
    When the operator runs `fw-audit all-in-one <fixture> -o <out> --platform all`
    Then `<out>/audit-report.xml` is a NetworkAuditReport
    And `<out>/ports-protocols.json` is written
    And Windows and nftables rulesets exist under `<out>/`
    And rulesets are deny-by-default
    And the report includes at least one flow classified unsafe

  Scenario: DMZ lab multi-host imports produce cross-zone graph artifacts
    Given example imports "examples/dmz-lab/imports" and hosts "examples/dmz-lab/hosts.yaml"
    When the operator runs `fw-audit all-in-one examples/dmz-lab/imports --hosts examples/dmz-lab/hosts.yaml -o <out> --platform all`
    Then three inventory hosts are present in the audit context
    And session flows include at least one internal→dmz path
    And `<out>/network-dataflow.dot` is written
    And Cisco IOS ACL rulesets are generated

  Scenario: report command writes XML and ports/protocols matrix only
    Given fixture export "tests/fixtures/netstat-windows.txt"
    When the operator runs `fw-audit report <fixture> -o <out>`
    Then `<out>/audit-report.xml` is written
    And `<out>/ports-protocols.json` is written

  Scenario: generate command writes platform rulesets
    Given fixture export "tests/fixtures/netstat-windows.txt"
    When the operator runs `fw-audit generate <fixture> -o <out> --platform windows`
    Then a Windows PowerShell ruleset exists under `<out>/`
