"""Detect Linux distribution family for tailored harden install scripts."""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class DistroFamily(str, Enum):
    """Supported package-manager families for harden stages."""

    REDHAT = "redhat"
    UBUNTU = "ubuntu"
    ARCH = "arch"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class HostDistro:
    """Resolved host OS facts used to tailor install scripts."""

    family: DistroFamily
    id: str
    id_like: tuple[str, ...]
    pretty_name: str
    package_manager: str
    is_omarchy: bool = False

    @property
    def supported(self) -> bool:
        return self.family != DistroFamily.UNKNOWN


def _parse_os_release(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        data[key] = value
    return data


def _family_from_ids(os_id: str, id_like: tuple[str, ...]) -> DistroFamily:
    tokens = {os_id, *id_like}
    # Omarchy and Arch share pacman; prefer Arch family before Debian-like checks.
    if tokens & {"arch", "archlinux", "manjaro", "endeavouros", "omarchy", "cachyos"}:
        return DistroFamily.ARCH
    if tokens & {
        "rhel",
        "centos",
        "fedora",
        "rocky",
        "almalinux",
        "ol",
        "amazon",
        "redhat",
    }:
        return DistroFamily.REDHAT
    if tokens & {"ubuntu", "debian", "linuxmint", "pop", "elementary", "raspbian"}:
        return DistroFamily.UBUNTU
    return DistroFamily.UNKNOWN


def _package_manager(family: DistroFamily) -> str:
    if family == DistroFamily.ARCH:
        return "pacman"
    if family == DistroFamily.REDHAT:
        return "dnf"
    if family == DistroFamily.UBUNTU:
        return "apt"
    return "unknown"


def detect_distro(
    os_release_path: Path | None = None,
    *,
    environ: dict[str, str] | None = None,
) -> HostDistro:
    """Read os-release (or overrides) and map to a supported harden family."""
    env = environ if environ is not None else os.environ
    path = os_release_path or Path(env.get("FW_AUDIT_OS_RELEASE", "/etc/os-release"))

    raw = ""
    if path.is_file():
        raw = path.read_text(encoding="utf-8", errors="replace")
    parsed = _parse_os_release(raw)

    os_id = (parsed.get("ID") or env.get("ID") or "unknown").lower()
    id_like_raw = parsed.get("ID_LIKE") or env.get("ID_LIKE") or ""
    id_like = tuple(t.lower() for t in id_like_raw.split() if t)
    pretty = parsed.get("PRETTY_NAME") or parsed.get("NAME") or os_id
    family = _family_from_ids(os_id, id_like)
    return HostDistro(
        family=family,
        id=os_id,
        id_like=id_like,
        pretty_name=pretty,
        package_manager=_package_manager(family),
        is_omarchy=os_id == "omarchy" or "omarchy" in id_like,
    )
