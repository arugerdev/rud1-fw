// Package wireguard reads and writes WireGuard INI-style configuration files
// and reports connection state.
package wireguard

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/platform"
)

// Status holds the current WireGuard interface configuration and connection state.
type Status struct {
	Interface           string
	PublicKey           string    // the PEER (hub) public key parsed from [Peer]
	PrivateKey          string    // only in memory, never serialised
	Address             string
	DNS                 string
	Endpoint            string    // peer endpoint
	AllowedIPs          string
	PersistentKeepalive int       // seconds; 0 = omitted
	Connected           bool
	LastHandshake       time.Time
}

// PeerAssignment is the [Peer] block the cloud pushes back to the agent in
// the heartbeat response, plus the Address the hub allocated for this device.
// ApplyPeer materialises a full wg0.conf from this plus the private key on disk.
type PeerAssignment struct {
	ServerPublicKey     string
	Endpoint            string
	Address             string // e.g. "10.200.1.7/32" — written to [Interface]
	AllowedIPs          string // e.g. "10.200.0.0/16"
	DNS                 string // optional
	PersistentKeepalive int    // seconds, typically 25
}

// Read parses a WireGuard config file in INI format.
func Read(configPath string) (*Status, error) {
	f, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("read wireguard config: %w", err)
	}
	defer f.Close()

	st := &Status{
		Interface: interfaceNameFromPath(configPath),
	}

	section := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch section {
		case "interface":
			switch key {
			case "PrivateKey":
				st.PrivateKey = value
			case "Address":
				st.Address = value
			case "DNS":
				st.DNS = value
			}
		case "peer":
			switch key {
			case "PublicKey":
				st.PublicKey = value
			case "Endpoint":
				st.Endpoint = value
			case "AllowedIPs":
				st.AllowedIPs = value
			case "PersistentKeepalive":
				if n, err := parseInt(value); err == nil {
					st.PersistentKeepalive = n
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan wireguard config: %w", err)
	}

	st.Connected = IsConnected(st.Interface)
	return st, nil
}

// Write creates or overwrites a WireGuard config file at configPath.
func Write(configPath string, cfg *Status) error {
	if err := platform.EnsureDir(filepath.Dir(configPath)); err != nil {
		return fmt.Errorf("ensure config dir: %w", err)
	}

	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	if cfg.PrivateKey != "" {
		fmt.Fprintf(&sb, "PrivateKey = %s\n", cfg.PrivateKey)
	}
	if cfg.Address != "" {
		fmt.Fprintf(&sb, "Address = %s\n", cfg.Address)
	}
	if cfg.DNS != "" {
		fmt.Fprintf(&sb, "DNS = %s\n", cfg.DNS)
	}
	sb.WriteString("\n[Peer]\n")
	if cfg.PublicKey != "" {
		fmt.Fprintf(&sb, "PublicKey = %s\n", cfg.PublicKey)
	}
	if cfg.Endpoint != "" {
		fmt.Fprintf(&sb, "Endpoint = %s\n", cfg.Endpoint)
	}
	if cfg.AllowedIPs != "" {
		fmt.Fprintf(&sb, "AllowedIPs = %s\n", cfg.AllowedIPs)
	}
	if cfg.PersistentKeepalive > 0 {
		fmt.Fprintf(&sb, "PersistentKeepalive = %d\n", cfg.PersistentKeepalive)
	}

	tmp := configPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return fmt.Errorf("write wireguard config: %w", err)
	}
	return os.Rename(tmp, configPath)
}

// IsConnected checks whether the WireGuard interface is up.
// On simulated hardware it always returns false.
func IsConnected(interfaceName string) bool {
	if platform.SimulateHardware() {
		return false
	}
	// Check /proc/net/if_inet6 for the interface name (works for IPv6-capable interfaces).
	data, err := os.ReadFile("/proc/net/if_inet6")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 6 && fields[5] == interfaceName {
				return true
			}
		}
	}
	// Fallback: check /sys/class/net/<iface>/operstate.
	state, err := os.ReadFile("/sys/class/net/" + interfaceName + "/operstate")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(state)) == "up"
}

// interfaceNameFromPath derives the WireGuard interface name from the config path
// (e.g. "/etc/wireguard/wg0.conf" → "wg0").
func interfaceNameFromPath(configPath string) string {
	base := filepath.Base(configPath)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// ReadOwnPubkey reads the device's own WireGuard public key from a world-
// readable mirror file (typically /etc/rud1-agent/wg-pubkey.txt, written by
// deploy/rpi/install.sh). Returns the trimmed key. Empty + nil if the file
// is empty (treated the same as missing by callers).
func ReadOwnPubkey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read own pubkey: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// LatestHandshake returns the most recent handshake time across all peers of
// the given WireGuard interface by invoking `wg show <iface> latest-handshakes`
// (one `<pubkey>\t<unix-seconds>` line per peer).
//
// Returns the zero time (never handshaked) when wg reports 0 or when no peers
// are present. Returns an error when the wg binary is missing or the command
// fails — callers should treat that as "unknown, don't surface a timestamp".
//
// On simulated hardware this is a no-op that returns the zero time with nil
// error, so local dev panels can render "disconnected" without warnings.
func LatestHandshake(interfaceName string) (time.Time, error) {
	if platform.SimulateHardware() {
		return time.Time{}, nil
	}
	out, err := exec.Command("wg", "show", interfaceName, "latest-handshakes").Output()
	if err != nil {
		return time.Time{}, fmt.Errorf("wg show latest-handshakes: %w", err)
	}
	var latest int64
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		secs, err := parseInt64(fields[len(fields)-1])
		if err != nil {
			continue
		}
		if secs > latest {
			latest = secs
		}
	}
	if latest == 0 {
		return time.Time{}, nil
	}
	return time.Unix(latest, 0), nil
}

func parseInt64(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit")
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}

// ApplyPeer writes a full wg0.conf (Interface + Peer) derived from `peer`
// plus the private key at `privkeyPath`, then restarts the wg-quick service
// so the kernel picks up the new config atomically.
//
// On simulated hardware the systemctl invocation is skipped (the conf is
// still written so developers can inspect it).
func ApplyPeer(configPath, privkeyPath string, peer PeerAssignment) error {
	privData, err := os.ReadFile(privkeyPath)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	privkey := strings.TrimSpace(string(privData))
	if privkey == "" {
		return fmt.Errorf("private key at %s is empty", privkeyPath)
	}

	iface := interfaceNameFromPath(configPath)
	cfg := &Status{
		Interface:           iface,
		PrivateKey:          privkey,
		Address:             peer.Address,
		DNS:                 peer.DNS,
		PublicKey:           peer.ServerPublicKey,
		Endpoint:            peer.Endpoint,
		AllowedIPs:          peer.AllowedIPs,
		PersistentKeepalive: peer.PersistentKeepalive,
	}
	if err := Write(configPath, cfg); err != nil {
		return err
	}

	if platform.SimulateHardware() {
		log.Info().
			Str("interface", iface).
			Str("address", peer.Address).
			Msg("wireguard: peer written (simulated — not restarting wg-quick)")
		return nil
	}

	unit := "wg-quick@" + iface + ".service"
	cmd := exec.Command("systemctl", "restart", unit)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restart %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
	}
	log.Info().
		Str("interface", iface).
		Str("address", peer.Address).
		Str("endpoint", peer.Endpoint).
		Msg("wireguard: peer applied, interface restarted")
	return nil
}

// parseInt trims whitespace and converts decimal digits. Local helper to
// avoid pulling strconv into every call site; returns (0, error) on bad input.
func parseInt(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
