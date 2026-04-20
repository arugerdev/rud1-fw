#!/usr/bin/env bash
set -euo pipefail

BINARY_URL="${BINARY_URL:-}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/rud1-agent"
DATA_DIR="/var/lib/rud1-agent"
LOG_DIR="/var/log/rud1-agent"
SERVICE_FILE="/etc/systemd/system/rud1-agent.service"

# ── Checks ────────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: This script must be run as root." >&2
  exit 1
fi

if ! command -v systemctl &>/dev/null; then
  echo "ERROR: systemd is required." >&2
  exit 1
fi

# ── Install binary ────────────────────────────────────────────────────────────

if [[ -n "$BINARY_URL" ]]; then
  echo "→ Downloading rud1-agent from $BINARY_URL"
  curl -fsSL "$BINARY_URL" -o "$INSTALL_DIR/rud1-agent"
elif [[ -f "./rud1-agent" ]]; then
  echo "→ Installing local ./rud1-agent"
  cp ./rud1-agent "$INSTALL_DIR/rud1-agent"
else
  echo "→ Building from source (requires Go 1.23+)"
  go build -o "$INSTALL_DIR/rud1-agent" ./cmd/rud1-agent
fi

chmod 755 "$INSTALL_DIR/rud1-agent"

# ── Create directories ────────────────────────────────────────────────────────

mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
chmod 700 "$DATA_DIR"

# ── Config file ───────────────────────────────────────────────────────────────

if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
  echo "→ Installing default config to $CONFIG_DIR/config.yaml"
  cat > "$CONFIG_DIR/config.yaml" <<'EOF'
log_level: info

server:
  host: 0.0.0.0
  port: 7070
  allowed_origins:
    - http://rud1.local
    - http://localhost:5173

cloud:
  enabled: true
  base_url: https://rud1.es
  api_secret: ""
  heartbeat_interval: 60s

vpn:
  interface: wg0
  config_path: /etc/wireguard/wg0.conf
EOF
  echo "  → Edit $CONFIG_DIR/config.yaml and set cloud.api_secret before starting."
fi

# ── Systemd service ───────────────────────────────────────────────────────────

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
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rud1-agent

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable rud1-agent
systemctl start rud1-agent

echo ""
echo "✓ rud1-agent installed and started."
echo "  Status:  systemctl status rud1-agent"
echo "  Logs:    journalctl -u rud1-agent -f"
echo "  Config:  $CONFIG_DIR/config.yaml"
echo ""
echo "  → The registration code will be printed in the agent logs."
echo "  → Enter it in your rud1-es dashboard to register this device."
