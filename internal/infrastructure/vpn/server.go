package wireguard

// WireGuard SERVER-side helpers.
//
// Post-2026-04-22 (no hub): each Raspberry runs its own wg0 as a server, not a
// client of a central hub. Identity (private/public key) is generated on the
// device at first boot and persisted in a world-writable-denied location.
// Clients (the user's PC) download a `.conf` from rud1.es pointing to this
// Pi's public endpoint, and the cloud pushes their (pubkey, allowed-ip)
// pairs back in the heartbeat response so the agent can `wg set` them live
// without restarting the interface.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/platform"
)

// DefaultListenPort is the UDP port wg0 binds to on the Pi. Matches the
// default in all rud1-es-generated client configs; overridable from YAML.
const DefaultListenPort = 51820

// ServerSpec is the minimal state needed to materialise the [Interface]
// section of wg0.conf. Peers are added out-of-band via AddPeer/RemovePeer so
// adding a user doesn't require a tunnel restart (which would drop every
// other active client).
type ServerSpec struct {
	Interface    string // e.g. "wg0"
	PrivateKey   string // base64, never logged
	AddressCIDR  string // e.g. "10.77.42.1/24"
	ListenPort   int    // UDP port
	PostUp       string // optional — LAN routing hook (iptables MASQUERADE)
	PostDown     string
}

// RuntimePeer describes one [Peer] block in the live `wg show`-equivalent
// view. Returned by ListPeers so the agent can diff against what the cloud
// says the peer set should be.
type RuntimePeer struct {
	PublicKey     string
	AllowedIPs    string
	LatestHshake  time.Time // zero if never
}

// EnsureKeypair generates a new (privkey, pubkey) pair with `wg genkey`
// iff `privkeyPath` doesn't already exist. Permissions: 0600 on the
// private key, 0644 on the public key. Returns the public key (always),
// even when the pair already existed.
//
// On simulated hardware this writes placeholder strings so local dev can
// still render the "device identity" card with something plausible.
func EnsureKeypair(privkeyPath, pubkeyPath string) (string, error) {
	if err := platform.EnsureDir(filepath.Dir(privkeyPath)); err != nil {
		return "", fmt.Errorf("ensure key dir: %w", err)
	}
	if data, err := os.ReadFile(pubkeyPath); err == nil {
		// Pair already exists — trust it. Regenerating would break every
		// client .conf that's been issued for this device.
		return strings.TrimSpace(string(data)), nil
	}
	if _, err := os.Stat(privkeyPath); err == nil {
		// Private key exists but public is missing — rederive it.
		pub, derr := derivePubkey(privkeyPath)
		if derr != nil {
			return "", derr
		}
		if werr := os.WriteFile(pubkeyPath, []byte(pub+"\n"), 0o644); werr != nil {
			return "", fmt.Errorf("write pubkey mirror: %w", werr)
		}
		return pub, nil
	}

	if platform.SimulateHardware() {
		priv := "SIMULATED_PRIVKEY_DO_NOT_USE=="
		pub := "SIMULATED_PUBKEY_DO_NOT_USE=="
		_ = os.WriteFile(privkeyPath, []byte(priv+"\n"), 0o600)
		_ = os.WriteFile(pubkeyPath, []byte(pub+"\n"), 0o644)
		log.Warn().Msg("wireguard: simulated keypair written (dev only)")
		return pub, nil
	}

	out, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", fmt.Errorf("wg genkey: %w", err)
	}
	priv := strings.TrimSpace(string(out))
	if err := os.WriteFile(privkeyPath, []byte(priv+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write privkey: %w", err)
	}
	pub, err := derivePubkey(privkeyPath)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(pubkeyPath, []byte(pub+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write pubkey mirror: %w", err)
	}
	log.Info().Str("pubkey", pub).Msg("wireguard: new server keypair generated")
	return pub, nil
}

// derivePubkey pipes the private key into `wg pubkey`. Split out so
// EnsureKeypair can recover from a missing mirror without regenerating.
func derivePubkey(privkeyPath string) (string, error) {
	priv, err := os.ReadFile(privkeyPath)
	if err != nil {
		return "", fmt.Errorf("read privkey: %w", err)
	}
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = bytes.NewReader(priv)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("wg pubkey: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// WriteServerConfig writes /etc/wireguard/<iface>.conf describing wg0 as a
// server (only [Interface] — peers are added via wg set, not persisted in
// the file, because wg-quick strip would drop them on restart anyway). The
// generated file is atomic (tmp + rename) and 0600.
func WriteServerConfig(configPath string, spec ServerSpec) error {
	if err := platform.EnsureDir(filepath.Dir(configPath)); err != nil {
		return fmt.Errorf("ensure config dir: %w", err)
	}

	port := spec.ListenPort
	if port <= 0 {
		port = DefaultListenPort
	}
	var sb strings.Builder
	sb.WriteString("# Rud1 WireGuard server — auto-generated, do not edit.\n")
	sb.WriteString("# Peers are added dynamically via `wg set` — restarting wg-quick\n")
	sb.WriteString("# drops them; the agent re-applies on next heartbeat.\n\n")
	sb.WriteString("[Interface]\n")
	fmt.Fprintf(&sb, "PrivateKey = %s\n", spec.PrivateKey)
	fmt.Fprintf(&sb, "Address = %s\n", spec.AddressCIDR)
	fmt.Fprintf(&sb, "ListenPort = %d\n", port)
	if spec.PostUp != "" {
		fmt.Fprintf(&sb, "PostUp = %s\n", spec.PostUp)
	}
	if spec.PostDown != "" {
		fmt.Fprintf(&sb, "PostDown = %s\n", spec.PostDown)
	}

	tmp := configPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return fmt.Errorf("write wireguard server config: %w", err)
	}
	return os.Rename(tmp, configPath)
}

// RestartServer brings the interface up (or restarts it, if already up).
// No-op on simulated hardware so a dev machine doesn't need root.
func RestartServer(iface string) error {
	if platform.SimulateHardware() {
		return nil
	}
	unit := "wg-quick@" + iface + ".service"
	cmd := exec.Command("systemctl", "restart", unit)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restart %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// AddPeer registers a client peer with the running WG interface, without
// touching the persistent config file. Idempotent: calling it again with
// the same pubkey+allowed-ips is a no-op from the kernel's point of view.
// `persistentKeepalive` is optional (0 = omitted); clients that sit behind
// NAT benefit from a ~25s keepalive to keep the mapping warm.
func AddPeer(iface, pubkey, allowedIPs string, persistentKeepalive int) error {
	if platform.SimulateHardware() {
		log.Info().
			Str("iface", iface).
			Str("pubkey", pubkey).
			Str("allowed_ips", allowedIPs).
			Msg("wireguard: add peer (simulated — not applied)")
		return nil
	}
	args := []string{"set", iface, "peer", pubkey, "allowed-ips", allowedIPs}
	if persistentKeepalive > 0 {
		args = append(args, "persistent-keepalive", fmt.Sprintf("%d", persistentKeepalive))
	}
	cmd := exec.Command("wg", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg set peer: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RemovePeer drops a peer from the live interface. Safe to call on a pubkey
// that isn't present (wg treats it as a no-op).
func RemovePeer(iface, pubkey string) error {
	if platform.SimulateHardware() {
		return nil
	}
	cmd := exec.Command("wg", "set", iface, "peer", pubkey, "remove")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg remove peer: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ListPeers returns every [Peer] currently installed on `iface`, with the
// most recent handshake per peer. Used by the agent to diff against the
// cloud's desired peer set and revoke stale entries.
func ListPeers(iface string) ([]RuntimePeer, error) {
	if platform.SimulateHardware() {
		return nil, nil
	}
	// `wg show <iface> dump` has one line per peer with tab-separated fields:
	//   <pubkey>\t<psk>\t<endpoint>\t<allowed-ips>\t<latest-hs>\t<rx>\t<tx>\t<keepalive>
	// and a header line for the interface we skip.
	out, err := exec.Command("wg", "show", iface, "dump").Output()
	if err != nil {
		return nil, fmt.Errorf("wg show dump: %w", err)
	}
	var peers []RuntimePeer
	for i, line := range strings.Split(string(out), "\n") {
		if i == 0 {
			continue // interface header
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}
		peer := RuntimePeer{
			PublicKey:  fields[0],
			AllowedIPs: fields[3],
		}
		if secs, err := parseInt64(fields[4]); err == nil && secs > 0 {
			peer.LatestHshake = time.Unix(secs, 0)
		}
		peers = append(peers, peer)
	}
	return peers, nil
}

// ReadPrivateKey loads the server's private key from disk. Kept separate
// from EnsureKeypair so the heartbeat loop can fetch it without touching
// filesystem permissions unnecessarily.
func ReadPrivateKey(privkeyPath string) (string, error) {
	data, err := os.ReadFile(privkeyPath)
	if err != nil {
		return "", fmt.Errorf("read privkey: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}
