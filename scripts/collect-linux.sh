#!/usr/bin/env bash
# Collect Linux network profile for fw-audit (run on target host).
set -e
echo "# ip-route"
ip -4 route 2>/dev/null || ip route
echo "# resolv.conf"
if [ -f /etc/resolv.conf ]; then cat /etc/resolv.conf; fi
if command -v resolvectl >/dev/null 2>&1; then
  echo "# resolvectl"
  resolvectl status 2>/dev/null || true
fi
echo "# ip-link"
ip link 2>/dev/null || true
echo "# rfkill"
if command -v rfkill >/dev/null 2>&1; then rfkill list 2>/dev/null || true; fi
