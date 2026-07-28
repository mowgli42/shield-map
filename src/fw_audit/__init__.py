"""Firewall ruleset and network exposure audit tool.

Public library surface for programmatic consumers (SnarkSentinel, etc.):

    from fw_audit import analyze, diff, generate_local_only

Symbols are loaded lazily to avoid import cycles with report modules.
"""

from __future__ import annotations

from typing import Any

__version__ = "0.1.0"

_API_EXPORTS = frozenset(
    {
        "DEFAULT_GUARDIAN_SOCKET",
        "AnalyzeResult",
        "DiffChange",
        "DiffResult",
        "LocalOnlyProfile",
        "analyze",
        "diff",
        "generate_local_only",
        "load_audit_xml",
    }
)

__all__ = ["__version__", *_API_EXPORTS]


def __getattr__(name: str) -> Any:
    if name in _API_EXPORTS:
        from fw_audit import api as _api

        return getattr(_api, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)
