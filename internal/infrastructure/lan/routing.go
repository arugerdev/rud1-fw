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
	"time"

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
	forced bool             // sim / dry-run — never call iptables
	state  map[string]Route // key: target CIDR (normalised)
	source string           // WG peer subnet; set on Configure()
	uplink string           // uplink iface; set on Configure()

	// Wall-clock time of the last successful Apply that mutated kernel
	// state (or that confirmed an already-converged set with no error).
	// Surfaced via LastAppliedAt() for the heartbeat snapshot + the local
	// health endpoint so an operator can tell at a glance whether the
	// route list they pushed has actually landed in the kernel.
	lastAppliedAt time.Time
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
		_, ipnet, err := net.ParseCIDR(t)
		if err != nil {
			continue
		}
		// Always store the canonical "network/mask" string so two
		// equivalent inputs ("192.168.1.5/24" + "192.168.1.0/24")
		// dedupe. This matches the desired-config validator's output
		// shape so the manager's state and the cloud's view stay
		// byte-identical.
		canonical := ipnet.String()
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		normalised = append(normalised, canonical)
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
	// Stamp the apply timestamp regardless of per-rule errors — the "I
	// tried" signal is itself useful telemetry. Snapshot.Applied tells the
	// operator which rules actually made it; lastAppliedAt tells them
	// when the last attempt was.
	m.lastAppliedAt = time.Now().UTC()
	return applied, errs
}

// LastAppliedAt returns the wall-clock time of the most recent Apply()
// invocation. Zero value means Apply has never been called on this manager
// (e.g. early boot, or LAN routing disabled and never seeded). The returned
// time is safe to compare against time.Time{}.IsZero().
func (m *Manager) LastAppliedAt() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastAppliedAt
}

// Health is the structured snapshot the local panel + heartbeat ship to
// operators. Bundles the converged state (live route list) with the
// out-of-band system signals (ip_forward, source/uplink) needed to debug
// "why isn't my LAN reachable" without SSH'ing into the Pi.
type Health struct {
	Source        string    `json:"source"`
	Uplink        string    `json:"uplink"`
	IPForward     bool      `json:"ipForward"`
	Simulated     bool      `json:"simulated"`
	Routes        []Route   `json:"routes"`
	LastAppliedAt time.Time `json:"lastAppliedAt"`
}

// HealthSnapshot returns the current LAN-routing health bundle. Callers (the
// HTTP handler and the heartbeat builder) should treat the returned slice as
// caller-owned — the routes are deep-copied out of the manager's state map.
func (m *Manager) HealthSnapshot() Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	routes := make([]Route, 0, len(m.state))
	for _, r := range m.state {
		routes = append(routes, r)
	}
	return Health{
		Source:        m.source,
		Uplink:        m.uplink,
		IPForward:     IPForwardEnabled(),
		Simulated:     m.forced,
		Routes:        routes,
		LastAppliedAt: m.lastAppliedAt,
	}
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
// or "-D" to delete) against BOTH the nat/POSTROUTING chain (MASQUERADE) and
// the filter/FORWARD chain (ACCEPT outbound + conntrack-gated return). Source
// is the WG peer subnet (may be empty — the MASQUERADE rule then matches all
// outbound, which still funnels through the per-target -d match).
//
// Why FORWARD rules at all when the Pi-OS default policy is ACCEPT: stock Pi
// images install with no firewall, but operators frequently add UFW or a
// restrictive nftables stack later. Without the explicit ACCEPT rules the
// LAN-routing feature appears to "work" until the operator tightens forward
// policy and silently breaks tunnel→LAN reachability with no obvious clue
// from the rud1 panel. Installing matched rules makes the feature robust
// against that without changing default-deny systems' security posture (the
// rules are scoped to the WG /24 and the specific target subnet).
//
// No-op if simulated is true.
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

	// 1) MASQUERADE in nat/POSTROUTING — rewrites source IP to the uplink's
	//    so replies come back to the Pi instead of trying to route directly
	//    to the WG-only peer address.
	natArgs := []string{"-t", "nat", action, "POSTROUTING"}
	if source != "" {
		natArgs = append(natArgs, "-s", source)
	}
	natArgs = append(natArgs, "-d", target, "-o", uplink, "-j", "MASQUERADE")
	if err := invokeIPTablesIdempotent(action, "nat", "POSTROUTING", natArgs); err != nil {
		return err
	}

	// 2) FORWARD ACCEPT — outbound: WG peer → LAN target via uplink.
	fwdOutArgs := []string{"-t", "filter", action, "FORWARD"}
	if source != "" {
		fwdOutArgs = append(fwdOutArgs, "-s", source)
	}
	fwdOutArgs = append(fwdOutArgs, "-d", target, "-o", uplink, "-j", "ACCEPT")
	if err := invokeIPTablesIdempotent(action, "filter", "FORWARD", fwdOutArgs); err != nil {
		return err
	}

	// 3) FORWARD ACCEPT — return: LAN target → WG peer, gated by conntrack
	//    so we don't open arbitrary inbound traffic from the LAN side. The
	//    `-d source` clause keeps this scoped to packets actually destined
	//    back into the tunnel, even on systems where the operator has
	//    expanded conntrack to accept additional flows.
	fwdRetArgs := []string{"-t", "filter", action, "FORWARD"}
	fwdRetArgs = append(fwdRetArgs, "-s", target, "-i", uplink)
	if source != "" {
		fwdRetArgs = append(fwdRetArgs, "-d", source)
	}
	fwdRetArgs = append(fwdRetArgs, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	return invokeIPTablesIdempotent(action, "filter", "FORWARD", fwdRetArgs)
}

// invokeIPTablesIdempotent runs `iptables` with the supplied args, treating
// "rule already absent on -D" and "rule already present on -A" both as
// success — so a tear-down after a partial install (or a re-apply after a
// reboot that left rules in-kernel) doesn't error out and abort the rest of
// the route list.
func invokeIPTablesIdempotent(action, table, chain string, args []string) error {
	switch action {
	case "-D":
		check := exec.Command("iptables", append([]string{"-t", table, "-C", chain}, args[4:]...)...)
		if err := check.Run(); err != nil {
			return nil // rule absent → nothing to delete
		}
	case "-A":
		check := exec.Command("iptables", append([]string{"-t", table, "-C", chain}, args[4:]...)...)
		if err := check.Run(); err == nil {
			return nil // rule already present → idempotent re-apply
		}
	}
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s %s/%s: %s: %w", action, table, chain, strings.TrimSpace(string(out)), err)
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
