// Package wireguard reads and writes WireGuard INI-style configuration files
// and reports connection state.
package wireguard

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rud1-es/rud1-fw/internal/platform"
)

// Status holds the current WireGuard interface configuration and connection state.
type Status struct {
	Interface     string
	PublicKey     string
	PrivateKey    string    // only in memory, never serialised
	Address       string
	DNS           string
	Endpoint      string    // peer endpoint
	AllowedIPs    string
	Connected     bool
	LastHandshake time.Time
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
