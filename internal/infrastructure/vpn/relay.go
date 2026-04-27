package wireguard

// WireGuard CLIENT-side helpers for the agent-managed wg-relay tunnel.
//
// Distinct from server.go: wg0 is the Pi's WireGuard SERVER (peers are
// users), whereas wg-relay is the Pi's WireGuard CLIENT — exactly one
// peer (the rud1-vps relay) and an outbound endpoint. Both can run
// simultaneously on the same Pi without conflict because Linux WG
// interfaces are independent kernel objects keyed by name.
//
// The cloud is the single source of truth for whether wg-relay should
// be up: when the heartbeat response carries a `relayPeer` block, the
// agent calls ApplyRelay; when the field is absent (or nil), it calls
// TeardownRelay. Both calls are idempotent — applying a spec that
// matches the on-disk one is a no-op, and tearing down an already-
// absent interface is a no-op.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/platform"
)

// RelaySpec describes the full state needed to materialise a wg-relay
// config. The Pi's PrivateKey is reused from server.go (one keypair
// per device) — passed in here so the relay package doesn't need to
// know its filesystem location.
type RelaySpec struct {
	Interface           string // e.g. "wg-relay"
	PrivateKey          string // base64; same key as wg0
	AddressCIDR         string // e.g. "10.99.42.1/32"
	PeerPublicKey       string // VPS pubkey
	Endpoint            string // e.g. "vps.rud1.es:51820"
	AllowedIPs          string // e.g. "10.99.0.0/16"
	PersistentKeepalive int    // seconds; mandatory for outbound NAT keepalive
}

// fingerprint returns a stable hash of the spec's wire-affecting
// fields, used to detect "config didn't change, skip restart". The
// hash deliberately excludes PersistentKeepalive's exact value below
// 5s because the cloud might tweak it without us wanting to bounce
// the tunnel — but in practice it's always 25 today.
func (s RelaySpec) fingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%d",
		s.Interface, s.AddressCIDR, s.PeerPublicKey, s.Endpoint, s.AllowedIPs, s.PersistentKeepalive)
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// WriteRelayConfig writes /etc/wireguard/<iface>.conf describing the
// outbound tunnel. Atomic (tmp + rename) and 0600.
//
// We embed the fingerprint as a leading comment line so subsequent
// ApplyRelay calls can short-circuit when the spec is unchanged
// without parsing the file. Comparing the comment is faster than
// re-reading the kernel state via `wg show dump` and avoids spurious
// restarts that would briefly drop user sessions.
func WriteRelayConfig(configPath string, spec RelaySpec) error {
	if err := platform.EnsureDir(filepath.Dir(configPath)); err != nil {
		return fmt.Errorf("ensure config dir: %w", err)
	}
	port := spec.PersistentKeepalive
	if port <= 0 {
		port = 25
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# Rud1 WireGuard relay tunnel — auto-generated, do not edit.\n")
	fmt.Fprintf(&sb, "# Cloud-driven; absent `relayPeer` in the heartbeat tears this down.\n")
	fmt.Fprintf(&sb, "# fingerprint: %s\n\n", spec.fingerprint())

	sb.WriteString("[Interface]\n")
	fmt.Fprintf(&sb, "PrivateKey = %s\n", spec.PrivateKey)
	fmt.Fprintf(&sb, "Address = %s\n", spec.AddressCIDR)
	// No ListenPort: client-only. The kernel picks an ephemeral source
	// port on send; the VPS sees that port and pins it for response
	// packets — exactly the NAT-traversal property we want.

	sb.WriteString("\n[Peer]\n")
	fmt.Fprintf(&sb, "PublicKey = %s\n", spec.PeerPublicKey)
	fmt.Fprintf(&sb, "Endpoint = %s\n", spec.Endpoint)
	fmt.Fprintf(&sb, "AllowedIPs = %s\n", spec.AllowedIPs)
	fmt.Fprintf(&sb, "PersistentKeepalive = %d\n", port)

	tmp := configPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return fmt.Errorf("write wg-relay config: %w", err)
	}
	return os.Rename(tmp, configPath)
}

// ApplyRelay materialises the spec on disk and brings the interface up
// (or restarts it if it was already up with a different fingerprint).
// Returns true when an actual restart happened — callers can use that
// to log a brief "tunnel bounced" line rather than the noisier "applied
// new config".
//
// On simulated hardware this is a no-op that just writes the file so
// the dev panel can render the relay state without root.
func ApplyRelay(configPath string, spec RelaySpec) (restarted bool, err error) {
	prev := readFingerprint(configPath)

	if err := WriteRelayConfig(configPath, spec); err != nil {
		return false, err
	}

	if platform.SimulateHardware() {
		log.Info().
			Str("iface", spec.Interface).
			Str("endpoint", spec.Endpoint).
			Msg("wg-relay: applied (simulated — not started)")
		return false, nil
	}

	cur := spec.fingerprint()
	if prev == cur && relayInterfaceUp(spec.Interface) {
		// Same spec + iface already up — nothing to do. The kernel
		// state is in sync; bouncing the tunnel here would only drop
		// active user sessions for no gain.
		return false, nil
	}

	// Take the iface down first if it was up. wg-quick is idempotent
	// on `down` for an already-absent iface (returns non-zero but a
	// recognisable message), so we tolerate the failure path.
	if relayInterfaceUp(spec.Interface) {
		_ = runQuiet("wg-quick", "down", spec.Interface)
	}

	if out, derr := exec.Command("wg-quick", "up", spec.Interface).CombinedOutput(); derr != nil {
		return false, fmt.Errorf("wg-quick up %s: %w: %s",
			spec.Interface, derr, strings.TrimSpace(string(out)))
	}
	return true, nil
}

// TeardownRelay brings the wg-relay interface down (if up) and removes
// the config file. Idempotent — both steps tolerate the not-present
// case so the cloud's "tear down" command can be sent on every
// heartbeat that lacks a relayPeer block without churning the kernel.
func TeardownRelay(configPath, iface string) error {
	if !platform.SimulateHardware() && relayInterfaceUp(iface) {
		if out, err := exec.Command("wg-quick", "down", iface).CombinedOutput(); err != nil {
			// Don't return — we still want to clear the file so the
			// next ApplyRelay starts from a clean slate. Log the
			// failure for diagnosis.
			log.Warn().
				Str("iface", iface).
				Err(err).
				Str("output", strings.TrimSpace(string(out))).
				Msg("wg-relay: down command failed; continuing teardown")
		}
	}

	if err := os.Remove(configPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove relay config: %w", err)
	}
	return nil
}

// RelayStatus is the agent's snapshot of the wg-relay tunnel — used to
// populate HBVPNRelay in the heartbeat. Returns nil when the interface
// is absent (which is the steady state for direct-mode devices).
type RelayStatus struct {
	Up            bool
	Address       string // best-effort echo from the on-disk config
	Endpoint      string
	LatestHshake  time.Time
	BytesRx       uint64
	BytesTx       uint64
}

// ReadRelayStatus shells out to `wg show <iface> dump` and pulls the
// peer row (the VPS). Returns (nil, nil) when the iface is not up —
// that is the canonical "no relay assigned" state and not an error.
func ReadRelayStatus(iface, configPath string) (*RelayStatus, error) {
	if platform.SimulateHardware() {
		return nil, nil
	}
	if !relayInterfaceUp(iface) {
		return nil, nil
	}

	out, err := exec.Command("wg", "show", iface, "dump").Output()
	if err != nil {
		return nil, fmt.Errorf("wg show %s dump: %w", iface, err)
	}
	st := &RelayStatus{Up: true, Address: addressFromConfig(configPath)}
	lines := strings.Split(string(out), "\n")
	// Line 0 is the interface header; we want line 1 (the single
	// VPS peer). Anything beyond would be unexpected — a relay tunnel
	// has exactly one peer.
	if len(lines) < 2 {
		return st, nil
	}
	fields := strings.Split(strings.TrimSpace(lines[1]), "\t")
	if len(fields) < 7 {
		return st, nil
	}
	if ep := strings.TrimSpace(fields[2]); ep != "" && ep != "(none)" {
		st.Endpoint = ep
	}
	if secs, err := parseInt64(fields[4]); err == nil && secs > 0 {
		st.LatestHshake = time.Unix(secs, 0)
	}
	if rx, err := parseUint64(fields[5]); err == nil {
		st.BytesRx = rx
	}
	if tx, err := parseUint64(fields[6]); err == nil {
		st.BytesTx = tx
	}
	return st, nil
}

// relayInterfaceUp returns true iff the kernel knows about the named
// WireGuard interface. We use `wg show <iface>` (returns non-zero on
// missing iface) rather than `ip link show` because we only care about
// WG-managed state — a stray `ip link add` doesn't fool us.
func relayInterfaceUp(iface string) bool {
	if platform.SimulateHardware() {
		return false
	}
	cmd := exec.Command("wg", "show", iface)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

// readFingerprint pulls the `# fingerprint: <hex>` line out of an
// existing wg-relay.conf. Returns empty string when the file is
// absent or malformed — both cases mean "force a fresh apply", which
// is the safe default.
func readFingerprint(configPath string) string {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "# fingerprint:"); ok {
			return strings.TrimSpace(v)
		}
		if !strings.HasPrefix(line, "#") && line != "" {
			return ""
		}
	}
	return ""
}

// addressFromConfig pulls the [Interface] Address line out of the
// config so the agent can echo it back to the cloud in the heartbeat
// without re-deriving the value. Best-effort: failures return empty.
func addressFromConfig(configPath string) string {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(t, "Address ="); ok {
			return strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(t, "Address="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func runQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}
