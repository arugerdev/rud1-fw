#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# uninstall.sh — remove Rud1 agent + web panel from this device.
#
# Keeps $DATA_DIR (which holds the device identity / registration code) by
# default so reinstalling later re-registers as the same device. Pass
# RUD1_PURGE=1 to nuke everything including identity.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RUD1_PURGE="${RUD1_PURGE:-0}"

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }

say() { printf '→ %s\n' "$*"; }

say "Stopping rud1-agent"
systemctl disable --now rud1-agent 2>/dev/null || true
rm -f /etc/systemd/system/rud1-agent.service
systemctl daemon-reload

say "Removing agent binary"
rm -f /usr/local/bin/rud1-agent

say "Removing nginx site"
rm -f /etc/nginx/sites-enabled/rud1 /etc/nginx/sites-available/rud1
if [[ -d /var/www/rud1 ]]; then
  rm -rf /var/www/rud1
fi
if command -v nginx >/dev/null 2>&1; then
  nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
fi

say "Removing kernel module + sysctl drop-ins"
rm -f /etc/modules-load.d/rud1.conf /etc/sysctl.d/99-rud1.conf

if [[ "$RUD1_PURGE" == "1" ]]; then
  say "Purging config + data (RUD1_PURGE=1)"
  rm -rf /etc/rud1-agent /var/lib/rud1-agent
else
  say "Keeping /etc/rud1-agent and /var/lib/rud1-agent (set RUD1_PURGE=1 to remove)."
fi

echo "✓ Uninstalled."
