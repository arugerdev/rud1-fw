#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# build-release.sh — cross-compile the agent + build the web UI and pack
# them into a tarball that install.sh (on the Pi) knows how to consume.
#
# Run this on your development machine. Requires:
#   - go 1.23+
#   - node 20+ and npm
#   - tar, sha256sum
#
# Assumes the monorepo layout:
#     <repo-root>/rud1-fw          ← this repo (we're in deploy/rpi/)
#     <repo-root>/rud1-app         ← sibling repo with the Astro panel
#
# Pass RUD1_APP_DIR=… if your checkout differs.
#
# Output:
#     deploy/rpi/dist/rud1-release-<version>-linux-arm64.tar.gz
#     deploy/rpi/dist/rud1-release-<version>-linux-arm64.tar.gz.sha256
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
APP_DIR="${RUD1_APP_DIR:-$(cd "$FW_ROOT/../rud1-app" 2>/dev/null && pwd || true)}"
DIST_DIR="$SCRIPT_DIR/dist"
STAGE_DIR="$DIST_DIR/.stage"

# Accept GOARCH=arm for 32-bit Pi OS; default to arm64 (Pi 3 supports it).
GOARCH="${GOARCH:-arm64}"
GOOS="linux"

VERSION="$(cd "$FW_ROOT" && git describe --tags --always --dirty 2>/dev/null || echo "dev")"
COMMIT="$(cd "$FW_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "none")"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

TARBALL="$DIST_DIR/rud1-release-${VERSION}-${GOOS}-${GOARCH}.tar.gz"

log()  { printf '\033[1;34m→\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

command -v go >/dev/null || err "go is required (install 1.23+)"
command -v tar >/dev/null || err "tar is required"

if [[ -z "${APP_DIR:-}" || ! -d "$APP_DIR" ]]; then
  warn "rud1-app not found at \$RUD1_APP_DIR / ../rud1-app — the web panel will NOT be packaged."
  warn "Only the agent binary + config will be included. Pass RUD1_APP_DIR to include the UI."
  APP_DIR=""
fi

# ─── Clean stage ─────────────────────────────────────────────────────────────
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"/{bin,web,systemd,nginx,modules,sysctl,config}

# ─── Build agent ─────────────────────────────────────────────────────────────
log "Building rud1-agent ${VERSION} for ${GOOS}/${GOARCH}"
(
  cd "$FW_ROOT"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build \
      -trimpath \
      -ldflags "-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
      -o "$STAGE_DIR/bin/rud1-agent" \
      ./cmd/rud1-agent
)
chmod 755 "$STAGE_DIR/bin/rud1-agent"

# ─── Build web UI (if rud1-app available) ────────────────────────────────────
if [[ -n "$APP_DIR" ]]; then
  command -v npm >/dev/null || err "npm is required to build the web UI"
  log "Building rud1-app (Astro static output)"
  (
    cd "$APP_DIR"
    if [[ ! -d node_modules ]]; then
      npm install --no-audit --no-fund
    fi
    npm run build
  )
  if [[ ! -d "$APP_DIR/dist" ]]; then
    err "rud1-app build did not produce a dist/ folder"
  fi
  cp -r "$APP_DIR/dist/"* "$STAGE_DIR/web/"
  touch "$STAGE_DIR/web/.has-ui"
else
  echo "<!doctype html><meta charset=utf-8><title>Rud1</title><h1>Rud1 agent</h1><p>Web UI not bundled. Access the API at :7070.</p>" \
    > "$STAGE_DIR/web/index.html"
fi

# ─── Copy assets ─────────────────────────────────────────────────────────────
log "Copying install assets"
cp "$SCRIPT_DIR/install.sh"                              "$STAGE_DIR/install.sh"
cp "$SCRIPT_DIR/uninstall.sh"                            "$STAGE_DIR/uninstall.sh"
cp "$SCRIPT_DIR/assets/rud1-agent.service"               "$STAGE_DIR/systemd/rud1-agent.service"
cp "$SCRIPT_DIR/assets/rud1.nginx.conf"                  "$STAGE_DIR/nginx/rud1"
cp "$SCRIPT_DIR/assets/rud1-modules.conf"                "$STAGE_DIR/modules/rud1.conf"
cp "$SCRIPT_DIR/assets/rud1-sysctl.conf"                 "$STAGE_DIR/sysctl/99-rud1.conf"
cp "$SCRIPT_DIR/assets/config.yaml.template"             "$STAGE_DIR/config/config.yaml.template"
chmod 755 "$STAGE_DIR/install.sh" "$STAGE_DIR/uninstall.sh"

# Version manifest consumed by install.sh
cat > "$STAGE_DIR/VERSION" <<EOF
version=${VERSION}
commit=${COMMIT}
build_date=${BUILD_DATE}
goos=${GOOS}
goarch=${GOARCH}
has_web=$([[ -n "$APP_DIR" ]] && echo yes || echo no)
EOF

# ─── Pack ────────────────────────────────────────────────────────────────────
log "Packing ${TARBALL}"
mkdir -p "$DIST_DIR"
tar -C "$STAGE_DIR" -czf "$TARBALL" .
(cd "$DIST_DIR" && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256")

SIZE="$(du -h "$TARBALL" | cut -f1)"
log "Done."
echo
echo "  Release : $TARBALL"
echo "  Size    : $SIZE"
echo "  SHA256  : $(cat "$TARBALL.sha256" | cut -d' ' -f1)"
echo
echo "Next step — deploy to the Raspberry Pi:"
echo "  scp \"$TARBALL\" pi@rud1.local:/tmp/"
echo "  ssh pi@rud1.local 'sudo tar -C /tmp/rud1-release -xzf /tmp/$(basename "$TARBALL") \\"
echo "     --one-top-level=rud1-release --strip-components=0 && sudo /tmp/rud1-release/install.sh'"
echo
