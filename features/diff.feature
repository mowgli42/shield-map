Feature: fw-audit diff against baseline
  Compare two audit-report.xml snapshots for configuration drift
  (listeners, classifications, cross-zone flows). Aligns with
  `fw-audit diff` and `fw_audit.diff.compare`. Covered by
  `tests/test_diff.py`.

  Scenario: Drift between baseline and current exits non-zero with JSON findings
    Given a baseline audit-report.xml with listener tcp/445 (risky)
    And a current audit-report.xml that adds listener tcp/23 (unsafe)
    When the operator runs `fw-audit diff <baseline> <current> --format json`
    Then the process exits with code 1
    And stdout includes `"drift_detected": true`
    And stdout includes a LISTENER_ADDED finding

  Scenario: Identical snapshots report no drift
    Given the same audit-report.xml as baseline and current
    When the operator runs `fw-audit diff <baseline> <current> --format text --no-exit-code`
    Then the process exits with code 0
    And stdout includes "Drift detected: no"

  Scenario: Missing baseline file fails with exit code 2
    Given a missing baseline path and a valid current audit-report.xml
    When the operator runs `fw-audit diff <missing> <current>`
    Then the process exits with code 2
    And stderr reports that the baseline was not found
