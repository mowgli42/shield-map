# AGENTS.md - guide for AI coding agents

## Project context

shield-map is the `fw-audit` netstat/port audit CLI.
Start with `README.md`, `pyproject.toml`, and `tests/` before editing behavior.

## Local setup

Run from the repository root:

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Smoke test

```bash
.venv/bin/python -m pytest tests/ -q
```

## Agent notes

- Add or update tests for CLI parsing and report output changes.
- Keep command-line behavior backward compatible unless the task explicitly changes it.
- Preserve existing local user changes; stage only files you intentionally modify.

## Issue Tracking

This project uses **bd (beads)** for issue tracking. Run `bd prime` for workflow context, or install hooks with `bd hooks install` for automatic context injection.

Quick reference:

- `bd ready` - find unblocked work
- `bd create "Title" --type task --priority 2` - create an issue
- `bd close <id>` - close completed work
- `bd dolt push` - push Beads data when using a shared Beads remote

For full workflow details, run `bd prime`.
