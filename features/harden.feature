Feature: shield-up Linux harden stages
  Clear staged workflow: discover open ports → firewall config → apply rules →
  Fail2ban → optional OpenCanary → optional filtered DNS → optional Spamhaus DROP →
  shield-audit drift cron.
  Distro detection at startup tailors install scripts for Red Hat, Ubuntu, and
  Arch (including Omarchy). Aligns with `shield-up` / `fw-audit harden` and
  `fw_audit.harden.pipeline.run_harden`. Covered by `tests/test_harden.py`.

  Scenario: Scripts-only harden from ss fixture on Arch/Omarchy
    Given an ss export fixture and HostDistro family arch (omarchy)
    When the operator runs shield-up with --scripts-only and --no-opencanary --no-dns --no-drop
    Then discover copies/captures listening ports under out/imports/
    And configure writes nftables, Fail2ban, OpenCanary artifacts and audit-report.xml
    And harden-scripts/ contains pacman-based 01-install-deps.sh
    And harden-scripts/ also contains 07-setup-drop.sh and shield-drop-refresh.sh
    And firewall, fail2ban, and cron stages report dry-run
    And opencanary, dns, and drop stages are skipped

  Scenario: Distro-tailored package install blocks
    Given HostDistro families redhat, ubuntu, and arch
    When harden scripts are generated for each family
    Then install-deps uses dnf/yum, apt-get, or pacman respectively
    And DNS scripts reference 1.1.1.2 primary and 9.9.9.9 backup
    And DROP refresh scripts reference Spamhaus drop.txt / dropv6.txt and keep previous sets on failure
    And cron scripts install shield-audit for configuration drift

  Scenario: Optional DROP stage dry-run when flags omitted
    Given scripts-only harden with stages discover,configure,opencanary,dns,drop
    When install_opencanary / update_dns / install_drop are left unset
    Then opencanary, dns, and drop stages report dry-run with Spamhaus DROP messaging
