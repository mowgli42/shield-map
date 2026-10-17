"""Allow ``python -m fw_audit`` / ``python -m fw_audit.cli`` entry."""

from fw_audit.cli import app

if __name__ == "__main__":
    app()
