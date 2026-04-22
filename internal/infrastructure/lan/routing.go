// Package lan provides the LAN-exposure primitives used by the agent to let
// WireGuard peers reach devices on the Pi's LAN (PLCs, Ethernet/WiFi nodes).
//
// The live implementation shells out to `sysctl` and `iptables`. The
// simulated variant (Windows dev, RUD1_SIMULATE=1) keeps state in-memory so
// the HTTP API still round-trips correctly during local development.
package lan

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/platform"
)

// DefaultUplink is the interface name used when LANConfig.UplinkInterface
// is blank and auto-detection fails. Matches the stock Pi Ethernet name.
const DefaultUplink = "eth0"

// Route is a single LAN exposure rule. The SourceSubnet field is always the
// WG peer subnet (i.e. `10.77.N.0/24`) — packets FROM that network destined
// to TargetSubnet are NAT'd out of the uplink, so replies come back to the
// Pi and get routed back into the tunnel.
//
// At the API/config level we only ever store TargetSubnet + UplinkInterface;
// SourceSubnet is derived from the device's WG subnet at apply time.
type Route struct {
	TargetSubnet string `json:"targetSubnet"`
	Uplink       string `json:"uplink"`
	Applied      bool   `json:"applied"`
}

// Manager owns the current applied state. It is safe to call concurrently;
// every mutation goes through a Lock.
//
// NOTE: this manager is not the source of truth for the ROUTE LIST (that
// lives in config.LANConfig on disk). It only owns the mapping
// "declared target → applied-in-kernel bool" so the HTTP layer can tell
// the user which rules are live vs. pending.
type Manager struct {
	mu     sync.Mutex
	forced bool              // sim / dry-run — never call iptables
	state  map[string]Route  // key: target CIDR (normalised)
	source string            // WG peer subnet; set on Configure()
	uplink string            // uplink iface; set on Configure()
}

// NewManager creates a manager. The first Configure() call binds it to the
// WG peer subnet and the uplink interface.
func NewManager() *Manager {
	return &Manager{
		forced: platform.SimulateHardware(),
		state:  map[string]Route{},
	}
}

// Configure sets the WG source subnet and uplink interface. Safe to call
// multiple times — if the values changed, all live rules are re-applied
// with the new source/uplink on the next Apply().
func (m *Manager) Configure(sourceSubnet, uplink string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.source = strings.TrimSpace(sourceSubnet)
	if strings.TrimSpace(uplink) == "" {
		uplink = DefaultUplink
	}
	m.uplink = uplink
}

// Source returns the currently-configured WG source subnet.
func (m *Manager) Source() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.source
}

// Uplink returns the currently-configured uplink interface.
func (m *Manager) Uplink() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.uplink
}

// Simulated reports whether the manager is running in a stubbed environment
// (Windows dev / RUD1_SIMULATE=1). Useful for the HTTP layer to flag the
// response so the UI can warn the operator "these rules are not live".
func (m *Manager) Simulated() bool { return m.forced }

// Apply installs the desired set of target subnets, replacing the current
// live set. Returns the post-apply Route list (ordered the same as input)
// plus any per-rule errors (non-fatal — the rest of the list still applies).
//
// Enabling IP forwarding happens here too, so a caller can simply call
// Apply([]) to leave the system in a clean "no routes" state when the
// admin disables the feature.
func (m *Manager) Apply(targets []string) ([]Route, []error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normalised := make([]string, 0, len(targets))
	seen := make(map[string]bool, len(targets))
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(t); err != nil {
			continue
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		normalised = append(normalised, t)
	}

	var errs []error
	if len(normalised) > 0 {
		if err := enableIPForward(m.forced); err != nil {
			errs = append(errs, fmt.Errorf("enable ip_forward: %w", err))
		}
	}

	// Remove rules that are no longer desired.
	for target, r := range m.state {
		if seen[target] {
			continue
		}
		if err := runIPTables(m.forced, "-D", r.TargetSubnet, m.source, r.Uplink); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", target, err))
			continue
		}
		delete(m.state, target)
	}

	// Add / refresh desired rules.
	applied := make([]Route, 0, len(normalised))
	for _, target := range normalised {
		prev, hadPrev := m.state[target]
		if hadPrev && prev.Uplink == m.uplink && prev.Applied {
			applied = append(applied, prev)
			continue
		}
		// Drop any stale row with a different uplink before re-adding.
		if hadPrev {
			_ = runIPTables(m.forced, "-D", prev.TargetSubnet, m.source, prev.Uplink)
		}
		if err := runIPTables(m.forced, "-A", target, m.source, m.uplink); err != nil {
			errs = append(errs, fmt.Errorf("add %s: %w", target, err))
			r := Route{TargetSubnet: target, Uplink: m.uplink, Applied: false}
			m.state[target] = r
			applied = append(applied, r)
			continue
		}
		r := Route{TargetSubnet: target, Uplink: m.uplink, Applied: true}
		m.state[target] = r
		applied = append(applied, r)
	}
	return applied, errs
}

// Snapshot returns the current live routes (copy — caller may mutate).
func (m *Manager) Snapshot() []Route {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Route, 0, len(m.state))
	for _, r := range m.state {
		out = append(out, r)
	}
	return out
}

// ── low-level helpers ────────────────────────────────────────────────────────

func enableIPForward(simulated bool) error {
	if simulated {
		return nil
	}
	out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// IPForwardEnabled reports whether /proc/sys/net/ipv4/ip_forward is 1.
// Always true in simulated mode so the UI doesn't display a scary warning
// on dev environments.
func IPForwardEnabled() bool {
	if platform.SimulateHardware() {
		return true
	}
	out, err := exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "1"
}

// runIPTables invokes iptables with the given action (either "-A" to append
// or "-D" to delete) against the nat/POSTROUTING chain. Source is the WG peer
// subnet (may be empty — in that case the rule matches the whole uplink). No-op
// if simulated is true.
func runIPTables(simulated bool, action, target, source, uplink string) error {
	if simulated {
		log.Debug().
			Str("action", action).
			Str("target", target).
			Str("source", source).
			Str("uplink", uplink).
			Msg("lan: iptables call (simulated)")
		return nil
	}
	if strings.TrimSpace(uplink) == "" {
		uplink = DefaultUplink
	}
	args := []string{"-t", "nat", action, "POSTROUTING"}
	if source != "" {
		args = append(args, "-s", source)
	}
	args = append(args, "-d", target, "-o", uplink, "-j", "MASQUERADE")

	// On delete, iptables returns 1 when the rule isn't present; treat that
	// as non-fatal so callers can idempotently delete.
	if action == "-D" {
		check := exec.Command("iptables", append([]string{"-t", "nat", "-C", "POSTROUTING"}, args[4:]...)...)
		if err := check.Run(); err != nil {
			return nil // rule absent → nothing to delete
		}
	}
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %s: %w", action, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// DetectDefaultUplink returns the interface name used for the default route.
// Falls back to DefaultUplink on error or in simulated mode.
func DetectDefaultUplink() string {
	if platform.SimulateHardware() {
		return DefaultUplink
	}
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return DefaultUplink
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				return fields[i+1]
			}
		}
	}
	return DefaultUplink
}

// ValidateRoute normalises a CIDR and rejects strings that are not a valid
// IPv4 subnet. Disallows single-host masks (/32) and overlap with the
// forbiddenSource (the WG peer subnet) — that would route peers' own traffic
// back at themselves, which is never what the operator wants.
func ValidateRoute(cidr, forbiddenSource string) (string, error) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return "", errors.New("empty subnet")
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	if ip.To4() == nil {
		return "", fmt.Errorf("only IPv4 routes are supported (got %s)", cidr)
	}
	ones, _ := ipnet.Mask.Size()
	if ones >= 32 {
		return "", fmt.Errorf("route must cover more than one host (got /%d)", ones)
	}
	if forbiddenSource != "" {
		if _, src, err := net.ParseCIDR(forbiddenSource); err == nil {
			if src.Contains(ipnet.IP) || ipnet.Contains(src.IP) {
				return "", fmt.Errorf("route %s overlaps WG subnet %s", cidr, forbiddenSource)
			}
		}
	}
	return ipnet.String(), nil
}
