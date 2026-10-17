# Shared helpers for shield-map / shield-up / shield-audit (sourced, not executed).
# shellcheck shell=bash

_shield_repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
}

_shield_ensure_python() {
  local root="$1"
  if [[ -n "${SHIELD_PYTHON:-}" && -x "${SHIELD_PYTHON}" ]]; then
    echo "${SHIELD_PYTHON}"
    return 0
  fi
  if [[ -x "${root}/.venv/bin/python" ]]; then
    echo "${root}/.venv/bin/python"
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    command -v python3
    return 0
  fi
  echo "shield-*: python3 not found; create a venv:" >&2
  echo "  python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'" >&2
  return 1
}

_shield_ensure_package() {
  local root="$1"
  local py="$2"
  if ! "$py" -c "import fw_audit" 2>/dev/null; then
    echo "Installing fw-audit (shield-map) package ($py) ..." >&2
    "$py" -m pip install -e "${root}[dev]"
  fi
}

# _shield_run_entry <entrypoints_fn> [args...]
# entrypoints_fn is one of: shield_map | shield_up | shield_audit
_shield_run_entry() {
  local fn="$1"
  shift
  local root py
  root="$(_shield_repo_root)"
  py="$(_shield_ensure_python "$root")" || exit 127
  _shield_ensure_package "$root" "$py" || exit 127
  export PYTHONPATH="${root}/src${PYTHONPATH:+:$PYTHONPATH}"
  # Pass CLI args after -c so Typer sees them in sys.argv
  exec "$py" -c "from fw_audit.entrypoints import ${fn}; ${fn}()" "$@"
}
