Feature: fw-audit Linux harden stages
  Clear staged workflow: discover open ports → firewall config → apply rules →
  Fail2ban → optional OpenCanary → optional filtered DNS → fw-audit drift cron.
  Distro detection at startup tailors install scripts for Red Hat, Ubuntu, and
  Arch (including Omarchy). Aligns with `fw-audit harden` and
  `fw_audit.harden.pipeline.run_harden`. Covered by `tests/test_harden.py`.

  Scenario: Scripts-only harden from ss fixture on Arch/Omarchy
    Given an ss export fixture and HostDistro family arch (omarchy)
    When the operator runs harden with --scripts-only and --no-opencanary --no-dns
    Then discover copies/captures listening ports under out/imports/
    And configure writes nftables, Fail2ban, OpenCanary artifacts and audit-report.xml
    And harden-scripts/ contains pacman-based 01-install-deps.sh
    And firewall, fail2ban, and cron stages report dry-run
    And opencanary and dns stages are skipped

  Scenario: Distro-tailored package install blocks
    Given HostDistro families redhat, ubuntu, and arch
    When harden scripts are generated for each family
    Then install-deps uses dnf/yum, apt-get, or pacman respectively
    And DNS scripts reference 1.1.1.2 primary and 9.9.9.9 backup
    And cron scripts install fw-audit-drift for configuration drift
