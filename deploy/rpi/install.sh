#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# install.sh — Rud1 agent installer for Raspberry Pi (Raspberry Pi OS Lite,
# Bookworm or newer, 64-bit recommended but 32-bit also supported).
#
# Can be run in two ways:
#
#   1) From an unpacked release tarball (produced by build-release.sh):
#        sudo ./install.sh
#      Expected layout next to this script:
#        bin/rud1-agent  web/  systemd/  nginx/  modules/  sysctl/  config/
#
#   2) Stand-alone (no release present) — will try to build from source if
#      Go is installed and the script lives inside the rud1-fw checkout.
#
# Idempotent: safe to re-run to upgrade the binary / web UI.
#
# Environment overrides (optional):
#   RUD1_API_SECRET      — if set, writes it into the config without prompting
#   RUD1_HOSTNAME        — set the Pi's hostname (default: keep current)
#   RUD1_CLOUD_URL       — default https://rud1.es
#   RUD1_SKIP_APT        — 1 to skip apt updates (useful for re-runs)
#   RUD1_ENABLE_USBIP    — 1 (default) to enable USB/IP kernel modules
#   RUD1_DISABLE_NGINX   — 1 to skip installing nginx / the web panel
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Paths ────────────────────────────────────────────────────────────────────
INSTALL_BIN="/usr/local/bin/rud1-agent"
CONFIG_DIR="/etc/rud1-agent"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
DATA_DIR="/var/lib/rud1-agent"
WEB_ROOT="/var/www/rud1"
SERVICE_FILE="/etc/systemd/system/rud1-agent.service"
NGINX_SITE_AVAILABLE="/etc/nginx/sites-available/rud1"
NGINX_SITE_ENABLED="/etc/nginx/sites-enabled/rud1"
MODULES_FILE="/etc/modules-load.d/rud1.conf"
SYSCTL_FILE="/etc/sysctl.d/99-rud1.conf"

# ── Defaults / env ───────────────────────────────────────────────────────────
RUD1_API_SECRET="${RUD1_API_SECRET:-}"
RUD1_HOSTNAME="${RUD1_HOSTNAME:-}"
RUD1_CLOUD_URL="${RUD1_CLOUD_URL:-https://rud1.es}"
RUD1_SKIP_APT="${RUD1_SKIP_APT:-0}"
RUD1_ENABLE_USBIP="${RUD1_ENABLE_USBIP:-1}"
RUD1_DISABLE_NGINX="${RUD1_DISABLE_NGINX:-0}"
RUD1_WIFI_COUNTRY="${RUD1_WIFI_COUNTRY:-ES}"

log()   { printf '\033[1;34m→\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m!\033[0m %s\n' "$*" >&2; }
err()   { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

# ── Preflight ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || err "This script must run as root (use sudo)."
command -v systemctl >/dev/null || err "systemd is required."
command -v apt-get   >/dev/null || err "This installer targets Debian/Raspberry Pi OS."

ARCH="$(dpkg --print-architecture)"
case "$ARCH" in
  arm64|armhf) ;;
  *) warn "Unusual architecture '$ARCH' — continuing but YMMV." ;;
esac

log "Rud1 Raspberry Pi installer — arch=$ARCH"

# ── APT dependencies ─────────────────────────────────────────────────────────
if [[ "$RUD1_SKIP_APT" != "1" ]]; then
  log "Updating apt cache"
  apt-get update -y

  PKGS=(
    ca-certificates curl gnupg
    wireguard wireguard-tools
    network-manager              # WiFi client + setup-AP via nmcli
    modemmanager                 # LTE modem (Sierra Wireless MC7700 HAT)
    libqmi-utils                 # QMI tooling (qmicli) — ModemManager backend
    libmbim-utils                # MBIM tooling (mbimcli) — some Sierra FWs
    avahi-daemon                 # mDNS → rud1.local
    chrony                       # Time sync (cloud API requires clean TLS)
  )
  if [[ "$RUD1_ENABLE_USBIP" == "1" ]]; then
    PKGS+=( usbip hwdata )
  fi
  if [[ "$RUD1_DISABLE_NGINX" != "1" ]]; then
    PKGS+=( nginx-light )
  fi

  log "Installing: ${PKGS[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${PKGS[@]}"
fi

# ── NetworkManager takeover ──────────────────────────────────────────────────
# Bookworm ships NM by default. Older images (Bullseye) shipped dhcpcd. If
# dhcpcd is still running, disable it so NM can manage wlan0 without
# stepping on its toes.
if systemctl is-enabled dhcpcd >/dev/null 2>&1; then
  log "Disabling legacy dhcpcd (NetworkManager will manage interfaces)"
  systemctl disable --now dhcpcd 2>/dev/null || true
fi
# Ensure NM manages wlan0. Some RPi OS images blacklist it in
# /etc/NetworkManager/NetworkManager.conf — inject an 'unmanaged-devices='
# override only if NM is installed.
if [[ -d /etc/NetworkManager ]]; then
  install -d /etc/NetworkManager/conf.d
  cat > /etc/NetworkManager/conf.d/10-rud1.conf <<'EOF'
# Let NetworkManager own both the onboard radio (wlan0) and any USB-attached
# radios. Installed by rud1-agent.
[main]
plugins=keyfile
[keyfile]
unmanaged-devices=none
EOF
  systemctl enable --now NetworkManager 2>/dev/null || true
  systemctl enable --now ModemManager 2>/dev/null || true
fi

# ── Hostname ─────────────────────────────────────────────────────────────────
# Default: provision the device as `rud1` (so `http://rud1.local` resolves
# the moment Avahi comes up). After the agent boots and generates its
# RegistrationCode we refine it to `rud1-XXXX` further down so two units in
# the same LAN don't fight over `rud1.local`. Operators that pass an
# explicit RUD1_HOSTNAME keep full control.
apply_hostname() {
  local target="$1"
  local current
  current="$(hostnamectl --static 2>/dev/null || cat /etc/hostname)"
  if [[ "$current" == "$target" ]]; then
    return
  fi
  log "Setting hostname: $current → $target"
  hostnamectl set-hostname "$target"
  if grep -q "^127.0.1.1" /etc/hosts; then
    sed -i "s/^127.0.1.1.*/127.0.1.1\t${target}/" /etc/hosts
  else
    echo -e "127.0.1.1\t${target}" >> /etc/hosts
  fi
}

if [[ -n "$RUD1_HOSTNAME" ]]; then
  apply_hostname "$RUD1_HOSTNAME"
else
  current_host="$(hostnamectl --static 2>/dev/null || cat /etc/hostname)"
  # Only seed `rud1` when the box still has the stock Pi name (or empty).
  # An existing `rud1-*` (or any operator-chosen value) is left alone here;
  # the post-boot refinement below will tighten `rud1` → `rud1-XXXX` once
  # the registration code is known.
  if [[ -z "$current_host" || "$current_host" == "raspberrypi" ]]; then
    apply_hostname "rud1"
  fi
fi

# ── mDNS (rud1.local) ────────────────────────────────────────────────────────
if systemctl list-unit-files avahi-daemon.service >/dev/null 2>&1; then
  log "Enabling avahi-daemon (so the device is reachable at <hostname>.local)"
  systemctl enable --now avahi-daemon
fi

# ── Wireless regulatory domain ───────────────────────────────────────────────
# Without a country code the kernel refuses to broadcast on any channel,
# so the setup AP looks "up" but is invisible to phones. We apply RUD1_WIFI_COUNTRY
# (default ES) at install time and persist it through raspi-config so the
# kernel restores it after every reboot. The agent also re-applies it on
# AP raise as a defence in depth.
if command -v iw >/dev/null; then
  log "Applying wireless regulatory domain: $RUD1_WIFI_COUNTRY"
  iw reg set "$RUD1_WIFI_COUNTRY" 2>/dev/null || \
    warn "iw reg set $RUD1_WIFI_COUNTRY failed — agent will retry on first AP raise"
fi
if command -v raspi-config >/dev/null; then
  raspi-config nonint do_wifi_country "$RUD1_WIFI_COUNTRY" 2>/dev/null || true
fi

# ── Kernel modules (USB/IP + VPN) ────────────────────────────────────────────
if [[ "$RUD1_ENABLE_USBIP" == "1" ]]; then
  if [[ -f "$SCRIPT_DIR/modules/rud1.conf" ]]; then
    log "Installing $MODULES_FILE"
    cp "$SCRIPT_DIR/modules/rud1.conf" "$MODULES_FILE"
  else
    cat > "$MODULES_FILE" <<'EOF'
# Rud1 required kernel modules
usbip-core
vhci-hcd
usbip-host
EOF
  fi
  chmod 644 "$MODULES_FILE"

  log "Loading USB/IP modules now (ignoring errors if already loaded)"
  modprobe usbip-core 2>/dev/null || true
  modprobe vhci-hcd   2>/dev/null || true
  modprobe usbip-host 2>/dev/null || true
fi

# ── sysctl (ip_forward for VPN, etc.) ────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/sysctl/99-rud1.conf" ]]; then
  cp "$SCRIPT_DIR/sysctl/99-rud1.conf" "$SYSCTL_FILE"
  sysctl --system >/dev/null
fi

# ── WireGuard bootstrap (keys + skeleton conf + auto-start unit) ─────────────
# Goal: leave the device ready to participate in the cloud-managed mesh as soon
# as the backend issues a peer config. We generate a per-device keypair on
# first install, surface the public key to userspace, write a *skeleton*
# /etc/wireguard/wg0.conf with the private key only (no [Peer] yet), and
# enable wg-quick@wg0 so it auto-comes-up once the agent's
# `POST /api/vpn/config` endpoint (or a manual edit) writes the [Peer] block.
#
# Idempotent: re-running never overwrites the existing keys or any config that
# already has a [Peer] section (i.e. cloud-provisioned).
WG_DIR="/etc/wireguard"
WG_PRIV="$WG_DIR/privatekey"
WG_PUB="$WG_DIR/publickey"
WG_CONF="$WG_DIR/wg0.conf"
WG_PUB_PUBLIC="$CONFIG_DIR/wg-pubkey.txt"  # world-readable mirror (panel reads it)

install -d -m 0700 "$WG_DIR"

if command -v wg >/dev/null; then
  if [[ ! -s "$WG_PRIV" ]]; then
    log "Generating WireGuard keypair → $WG_DIR"
    umask 077
    wg genkey | tee "$WG_PRIV" >/dev/null
    wg pubkey < "$WG_PRIV" > "$WG_PUB"
    chmod 600 "$WG_PRIV"
    chmod 644 "$WG_PUB"
  else
    ok "WireGuard private key already present, keeping it"
    # Recompute pubkey if missing (e.g. someone deleted it).
    if [[ ! -s "$WG_PUB" ]]; then
      wg pubkey < "$WG_PRIV" > "$WG_PUB"
      chmod 644 "$WG_PUB"
    fi
  fi

  # Skeleton wg0.conf — only written if no config exists yet, OR if the
  # current config has no [Peer] section (i.e. still a skeleton). This way
  # we never clobber a cloud-issued peer block on re-install.
  WG_PRIV_VALUE="$(cat "$WG_PRIV")"
  if [[ ! -f "$WG_CONF" ]] || ! grep -q '^\[Peer\]' "$WG_CONF" 2>/dev/null; then
    log "Writing skeleton $WG_CONF (no [Peer] yet — cloud will provision)"
    umask 077
    cat > "$WG_CONF" <<EOF
# Rud1 WireGuard skeleton — written by install.sh.
# The agent overwrites this file once the cloud issues peer parameters via
#   POST /api/vpn/config
# Manual edits between [Interface] and the (future) [Peer] block are safe;
# re-running install.sh does NOT clobber a config that already has a [Peer].

[Interface]
PrivateKey = ${WG_PRIV_VALUE}
# Address = 10.200.x.y/32      ← assigned by the cloud during pairing
# DNS     = 10.200.0.1
# ListenPort is intentionally omitted: clients dial out, no inbound port.

# [Peer]                        ← appended by the agent or by the cloud
# PublicKey  = <server-pubkey>
# Endpoint   = vpn.rud1.es:51820
# AllowedIPs = 10.200.0.0/16
# PersistentKeepalive = 25
EOF
    chmod 600 "$WG_CONF"
  else
    ok "$WG_CONF already has a [Peer] block, leaving it untouched"
  fi

  # Mirror the pubkey under /etc/rud1-agent so the agent / panel can show it
  # without needing to read /etc/wireguard (which is 0700, root-only).
  install -d -m 0755 "$CONFIG_DIR"
  install -m 0644 "$WG_PUB" "$WG_PUB_PUBLIC"

  # Enable the auto-start target. wg-quick refuses to bring an interface up
  # without a [Peer], so this is a no-op until the cloud writes one — at
  # which point a `systemctl start wg-quick@wg0` (or a reboot) attaches it.
  if systemctl list-unit-files 'wg-quick@.service' >/dev/null 2>&1; then
    systemctl enable wg-quick@wg0.service >/dev/null 2>&1 || true
    # If the conf already has a [Peer], try to bring it up now (idempotent).
    if grep -q '^\[Peer\]' "$WG_CONF" 2>/dev/null; then
      log "Bringing wg0 up (config has a [Peer])"
      systemctl restart wg-quick@wg0.service 2>/dev/null || \
        warn "wg-quick@wg0 failed to start — check: journalctl -u wg-quick@wg0"
    fi
  fi
else
  warn "wg binary not found — skipping WireGuard bootstrap (was apt blocked?)"
fi

# ── Install binary ───────────────────────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/bin/rud1-agent" ]]; then
  log "Installing bundled agent binary → $INSTALL_BIN"
  install -m 0755 "$SCRIPT_DIR/bin/rud1-agent" "$INSTALL_BIN"
elif command -v go >/dev/null && [[ -d "$SCRIPT_DIR/../../cmd/rud1-agent" ]]; then
  log "Building agent from source (go build)"
  (cd "$SCRIPT_DIR/../.." && go build -trimpath -ldflags "-s -w" -o "$INSTALL_BIN" ./cmd/rud1-agent)
else
  err "No agent binary at $SCRIPT_DIR/bin/rud1-agent and no Go toolchain available to build."
fi

# ── Config ───────────────────────────────────────────────────────────────────
install -d -m 0755 "$CONFIG_DIR"
install -d -m 0700 "$DATA_DIR"

if [[ ! -f "$CONFIG_FILE" ]]; then
  log "Installing default config → $CONFIG_FILE"
  if [[ -f "$SCRIPT_DIR/config/config.yaml.template" ]]; then
    cp "$SCRIPT_DIR/config/config.yaml.template" "$CONFIG_FILE"
  else
    cat > "$CONFIG_FILE" <<EOF
log_level: info
server:
  host: 0.0.0.0
  port: 7070
  allowed_origins:
    - http://localhost:5173
    - http://localhost
    - http://rud1.local
    - http://rud1-*.local
cloud:
  enabled: true
  base_url: ${RUD1_CLOUD_URL}
  api_secret: ""
  heartbeat_interval: 60s
vpn:
  interface: wg0
  config_path: /etc/wireguard/wg0.conf
usb:
  bind_port: 3240
  usbip_enabled: true
  authorized_nets:
    - 10.200.0.0/16
EOF
  fi

  # Prompt or inject API secret
  if [[ -z "$RUD1_API_SECRET" && -t 0 ]]; then
    echo
    read -r -s -p "Enter the cloud DEVICE_API_SECRET (input hidden, blank to skip): " RUD1_API_SECRET
    echo
  fi
  if [[ -n "$RUD1_API_SECRET" ]]; then
    # Escape for sed: / & \
    esc="$(printf '%s' "$RUD1_API_SECRET" | sed -e 's/[\/&]/\\&/g')"
    sed -i "s|^\(\s*api_secret:\s*\).*|\1\"${esc}\"|" "$CONFIG_FILE"
    ok "api_secret written to $CONFIG_FILE"
  else
    warn "api_secret is empty — the agent will fail to reach the cloud until you edit"
    warn "  $CONFIG_FILE and run:  sudo systemctl restart rud1-agent"
  fi
  chmod 600 "$CONFIG_FILE"
else
  ok "Config already present, leaving $CONFIG_FILE untouched"
  # Still respect an injected secret on re-run
  if [[ -n "$RUD1_API_SECRET" ]]; then
    esc="$(printf '%s' "$RUD1_API_SECRET" | sed -e 's/[\/&]/\\&/g')"
    sed -i "s|^\(\s*api_secret:\s*\).*|\1\"${esc}\"|" "$CONFIG_FILE"
    ok "api_secret updated"
  fi
fi

# ── systemd unit ─────────────────────────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/systemd/rud1-agent.service" ]]; then
  install -m 0644 "$SCRIPT_DIR/systemd/rud1-agent.service" "$SERVICE_FILE"
else
  cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=Rud1 Device Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/rud1-agent -config /etc/rud1-agent/config.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rud1-agent

[Install]
WantedBy=multi-user.target
EOF
fi
systemctl daemon-reload
systemctl enable rud1-agent

# ── Web panel (nginx serving Astro static) ───────────────────────────────────
if [[ "$RUD1_DISABLE_NGINX" != "1" ]]; then
  if [[ -d "$SCRIPT_DIR/web" ]]; then
    log "Publishing web UI → $WEB_ROOT"
    install -d -m 0755 "$WEB_ROOT"
    # Clean stale files then copy fresh build
    find "$WEB_ROOT" -mindepth 1 -delete 2>/dev/null || true
    cp -r "$SCRIPT_DIR/web/"* "$WEB_ROOT/"
    chown -R www-data:www-data "$WEB_ROOT"
  fi

  if [[ -f "$SCRIPT_DIR/nginx/rud1" ]]; then
    log "Configuring nginx site"
    install -m 0644 "$SCRIPT_DIR/nginx/rud1" "$NGINX_SITE_AVAILABLE"
    ln -sfn "$NGINX_SITE_AVAILABLE" "$NGINX_SITE_ENABLED"
    # Drop the Debian default site if still enabled
    [[ -e /etc/nginx/sites-enabled/default ]] && rm -f /etc/nginx/sites-enabled/default
    nginx -t
    systemctl enable --now nginx
    systemctl reload nginx || systemctl restart nginx
  fi
fi

# ── Start / restart agent ────────────────────────────────────────────────────
log "Starting rud1-agent"
systemctl restart rud1-agent
sleep 2

if ! systemctl is-active --quiet rud1-agent; then
  err "rud1-agent failed to start. Check:  journalctl -u rud1-agent -n 100 --no-pager"
fi

# ── Registration code ────────────────────────────────────────────────────────
# The agent persists its identity under $DATA_DIR; try to surface the code.
REG_CODE=""
for _ in 1 2 3 4 5; do
  if [[ -f "$DATA_DIR/identity.json" ]]; then
    REG_CODE="$(grep -oE '"registration_code"[[:space:]]*:[[:space:]]*"[^"]+"' "$DATA_DIR/identity.json" | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
    [[ -n "$REG_CODE" ]] && break
  fi
  # Fallback: pull from journal
  REG_CODE="$(journalctl -u rud1-agent -n 200 --no-pager 2>/dev/null | grep -oE 'RUD1-[A-F0-9]{8}-[A-F0-9]{8}' | tail -1 || true)"
  [[ -n "$REG_CODE" ]] && break
  sleep 2
done

# ── Hostname refinement (rud1 → rud1-XXXX) ──────────────────────────────────
# Once we know the registrationCode, append its last 4 hex chars so two
# fresh units in the same LAN don't both claim `rud1.local`. We only touch
# the hostname when it's still the bare default we (or the Pi image) set —
# never when the operator has chosen something custom.
if [[ -z "$RUD1_HOSTNAME" && -n "$REG_CODE" ]]; then
  current_host="$(hostnamectl --static 2>/dev/null || cat /etc/hostname)"
  if [[ "$current_host" == "rud1" || "$current_host" == "raspberrypi" || -z "$current_host" ]]; then
    suffix="${REG_CODE//-/}"
    suffix="${suffix: -4}"
    apply_hostname "rud1-${suffix}"
    # Avahi picks up the new hostname on the next refresh; nudge it so the
    # device is reachable at the new <hostname>.local immediately.
    systemctl restart avahi-daemon 2>/dev/null || true
  fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
HOSTNAME="$(hostname)"
LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

echo
ok "Rud1 agent installed."
echo "  Host          : ${HOSTNAME}.local (${LAN_IP:-unknown})"
echo "  Agent API     : http://${HOSTNAME}.local:7070"
[[ "$RUD1_DISABLE_NGINX" != "1" ]] && \
echo "  Web panel     : http://${HOSTNAME}.local"
echo "  Service       : systemctl status rud1-agent"
echo "  Logs          : journalctl -u rud1-agent -f"
echo "  Config        : $CONFIG_FILE"
echo "  Data dir      : $DATA_DIR"
echo
if [[ -n "$REG_CODE" ]]; then
  echo "  ════════════════════════════════════════════════════"
  echo "   Registration code:  ${REG_CODE}"
  echo "  ════════════════════════════════════════════════════"
  echo "   Pair at: ${RUD1_CLOUD_URL}/dashboard/devices?pair=${REG_CODE}"
  echo
else
  warn "Could not read registration code yet. Watch the logs:"
  echo "     journalctl -u rud1-agent -f"
fi

# ── WireGuard public key ─────────────────────────────────────────────────────
if [[ -s "$WG_PUB" ]]; then
  WG_PUB_VALUE="$(cat "$WG_PUB")"
  WG_STATE="not connected (no [Peer] in $WG_CONF yet)"
  if ip link show wg0 >/dev/null 2>&1; then
    WG_STATE="up"
  fi
  echo "  ────────────────────────────────────────────────────"
  echo "   WireGuard public key:"
  echo "     ${WG_PUB_VALUE}"
  echo "   Interface state: ${WG_STATE}"
  echo "   Mirror (read-only): ${WG_PUB_PUBLIC}"
  echo "  ────────────────────────────────────────────────────"
  echo
fi
