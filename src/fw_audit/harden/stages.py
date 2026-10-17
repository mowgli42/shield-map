"""Ordered harden stage identifiers and result records."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class StageId(str, Enum):
    """Clear sequential stages for Linux harden workflow."""

    DISCOVER = "discover"
    CONFIGURE = "configure"
    FIREWALL = "firewall"
    FAIL2BAN = "fail2ban"
    OPENCANARY = "opencanary"
    DNS = "dns"
    DROP = "drop"
    CRON = "cron"


STAGE_ORDER: tuple[StageId, ...] = (
    StageId.DISCOVER,
    StageId.CONFIGURE,
    StageId.FIREWALL,
    StageId.FAIL2BAN,
    StageId.OPENCANARY,
    StageId.DNS,
    StageId.DROP,
    StageId.CRON,
)

STAGE_TITLES: dict[StageId, str] = {
    StageId.DISCOVER: "Discover open ports (ss/netstat)",
    StageId.CONFIGURE: "Produce firewall configuration from open ports",
    StageId.FIREWALL: "Apply host firewall rules (nftables)",
    StageId.FAIL2BAN: "Install and configure Fail2ban for open ports",
    StageId.OPENCANARY: "Install OpenCanary with defaults (optional)",
    StageId.DNS: "Update DNS to filtered resolvers (optional)",
    StageId.DROP: "Load Spamhaus DROP blocklist into nftables (optional)",
    StageId.CRON: "Schedule shield-audit cron for configuration drift",
}

# Alternate spellings accepted by --stages
_STAGE_ALIASES: dict[str, StageId] = {
    "spamhaus-drop": StageId.DROP,
    "spamhaus_drop": StageId.DROP,
}


@dataclass
class StageResult:
    stage: StageId
    status: str  # ok | skipped | failed | dry-run
    message: str = ""
    artifacts: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


def parse_stages(raw: str | None) -> list[StageId]:
    """Parse comma-separated stage names; empty/None → full order."""
    if not raw or not raw.strip():
        return list(STAGE_ORDER)
    selected: list[StageId] = []
    for part in raw.split(","):
        name = part.strip().lower()
        if not name:
            continue
        if name in _STAGE_ALIASES:
            selected.append(_STAGE_ALIASES[name])
            continue
        try:
            selected.append(StageId(name))
        except ValueError as exc:
            known = ", ".join(s.value for s in STAGE_ORDER)
            raise ValueError(f"Unknown stage {name!r}; choose from: {known}") from exc
    # Preserve canonical order even if user reorders flags.
    order = {s: i for i, s in enumerate(STAGE_ORDER)}
    return sorted(set(selected), key=lambda s: order[s])
