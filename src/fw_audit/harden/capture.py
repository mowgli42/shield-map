"""Live capture of listening ports for harden discover stage."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def capture_listening_ports(output_file: Path) -> tuple[Path, str]:
    """Run ss (preferred) or netstat and write the export for parsers.

    Returns (path, tool_name).
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)
    ss = shutil.which("ss")
    if ss:
        result = subprocess.run(
            [ss, "-tulpn"],
            check=True,
            capture_output=True,
            text=True,
        )
        output_file.write_text(result.stdout, encoding="utf-8")
        return output_file, "ss"

    netstat = shutil.which("netstat")
    if netstat:
        result = subprocess.run(
            [netstat, "-tulpn"],
            check=True,
            capture_output=True,
            text=True,
        )
        output_file.write_text(result.stdout, encoding="utf-8")
        return output_file, "netstat"

    raise RuntimeError(
        "Neither ss nor netstat found; install iproute2 (ss) or net-tools (netstat)."
    )
