package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/lan"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/sysstat"
	usblister "github.com/rud1-es/rud1-fw/internal/infrastructure/usb"
	wireguard "github.com/rud1-es/rud1-fw/internal/infrastructure/vpn"
)

// SystemHealthHandler serves GET /api/system/health — a consolidated
// diagnostic snapshot combining sysstat metrics (+ rolling percentiles),
// WireGuard peer summary, LAN routing state, and USB/IP session +
// revocation context in a single call. Intended for dashboards and probes
// that want one round-trip instead of hitting /api/system/stats,
// /api/vpn/peers, /api/lan/routes, /api/usbip/sessions and
// /api/usbip/revocations separately.
//
// The handler is read-only and degrades gracefully: if a sub-collector
// fails we log the error, append a human-readable entry to `warnings`,
// and null out just that section rather than 500 the whole response.
type SystemHealthHandler struct {
	collector *sysstat.Collector
	iface     string
	lanMgr    *lan.Manager
	usbipH    *USBIPHandler
}

// NewSystemHealthHandler wires the handler against the shared sysstat
// collector, the WireGuard interface name, the LAN manager (may be nil
// if LAN exposure is disabled at build wiring) and the USB/IP handler
// (may be nil on platforms without USB/IP support).
func NewSystemHealthHandler(
	collector *sysstat.Collector,
	iface string,
	lanMgr *lan.Manager,
	usbipH *USBIPHandler,
) *SystemHealthHandler {
	return &SystemHealthHandler{
		collector: collector,
		iface:     iface,
		lanMgr:    lanMgr,
		usbipH:    usbipH,
	}
}

// vpnHealthBlock is the nested VPN summary returned under the top-level
// `vpn` key. Kept separate from the full vpn/peers payload so the shape
// stays stable even if the peer list grows extra fields later.
type vpnHealthBlock struct {
	Interface     string `json:"interface"`
	PeersCount    int    `json:"peersCount"`
	ActivePeers   int    `json:"activePeers"`
	LastHandshake int64  `json:"lastHandshake"`
}

// healthLANRoute mirrors the (subnet, applied) tuple reported by the
// heartbeat (HBLANRoute) so the diagnostic endpoint uses the same shape
// the cloud already consumes.
type healthLANRoute struct {
	Subnet  string `json:"subnet"`
	Applied bool   `json:"applied"`
}

// healthLAN is the nested LAN block: current configured uplink, WG source
// subnet, `sysctl net.ipv4.ip_forward` state, simulated flag, and the
// live route list from lan.Manager.Snapshot(). LastAppliedAt is the
// wall-clock of the most recent Apply() call (RFC3339, UTC), or null
// when LAN routing has never been applied this boot — surfaces "the
// route list landed in the kernel at HH:MM" without a debug shell.
type healthLAN struct {
	Enabled       bool             `json:"enabled"`
	Uplink        string           `json:"uplink"`
	Source        string           `json:"source"`
	IPForward     bool             `json:"ipForward"`
	Simulated     bool             `json:"simulated"`
	Routes        []healthLANRoute `json:"routes"`
	LastAppliedAt *time.Time       `json:"lastAppliedAt,omitempty"`
	// Iter 59: same shape the cloud surfaces — count of consecutive
	// failed Apply() calls. Always emitted (0 in steady state) so the
	// rud1-app local panel can render "failing × N" without depending on
	// cloud round-trips.
	ApplyErrorStreak int `json:"applyErrorStreak"`
	// Iter 59: digest of the first per-rule error from the most recent
	// Apply (omitted when last apply was clean). Mirrors the heartbeat
	// HBLAN.lastApplyError field.
	LastApplyError string `json:"lastApplyError,omitempty"`
}

// healthUSBIP is the nested USB/IP block: daemon flag, counts derived
// from the authoritative USBIPServer + sysfs session parse, and the tail
// of the revocation ring buffer for recent-events context.
type healthUSBIP struct {
	Enabled            bool              `json:"enabled"`
	ExportedCount      int               `json:"exportedCount"`
	InUseCount         int               `json:"inUseCount"`
	RecentRevocations  []RevocationEntry `json:"recentRevocations"`
}

// systemHealthResponse is the JSON payload served by Health.
// Every sub-section is nullable so a partial failure (e.g. `wg show`
// missing on a dev box, or usbip tooling absent) still produces a
// structurally valid response the client can parse. `Warnings` surfaces
// which collectors degraded so operators don't have to diff logs.
type systemHealthResponse struct {
	Timestamp   int64                        `json:"timestamp"`
	System      *sysstat.Stats               `json:"system"`
	Percentiles *sysstat.PercentilesSnapshot `json:"percentiles"`
	VPN         *vpnHealthBlock              `json:"vpn"`
	LAN         *healthLAN                   `json:"lan"`
	USBIP       *healthUSBIP                 `json:"usbip"`
	Warnings    []string                     `json:"warnings,omitempty"`
}

// Health handles GET /api/system/health.
func (h *SystemHealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	// 6s wraps the whole handler: sysstat's CPU sample is ~250ms, the
	// wg-show shells are milliseconds, and we want to fail the request
	// before Chi's WriteTimeout kicks in.
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()

	resp := systemHealthResponse{
		Timestamp: time.Now().Unix(),
	}

	// --- sysstat snapshot + percentiles ----------------------------------
	if h.collector != nil {
		snap, err := h.collector.Snapshot(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("system health: sysstat snapshot failed")
			resp.Warnings = append(resp.Warnings, fmt.Sprintf("sysstat: %v", err))
		} else {
			resp.System = snap
		}
		// Percentiles are only meaningful once the rolling window has
		// enough samples — mirror the /api/system/stats?percentiles=1
		// gating so clients treat both endpoints consistently.
		pct := h.collector.Percentiles()
		if pct.WindowSize >= 5 {
			resp.Percentiles = &pct
		}
	}

	// --- WireGuard peer summary ------------------------------------------
	if h.iface != "" {
		block := &vpnHealthBlock{Interface: h.iface}
		peers, err := wireguard.ListPeers(h.iface)
		if err != nil {
			log.Warn().Err(err).Str("iface", h.iface).Msg("system health: wireguard list peers failed")
			resp.Warnings = append(resp.Warnings, fmt.Sprintf("vpn: %v", err))
		} else {
			block.PeersCount = len(peers)
			now := time.Now()
			var latest int64
			for _, p := range peers {
				if p.LatestHshake.IsZero() {
					continue
				}
				hs := p.LatestHshake.Unix()
				if hs > latest {
					latest = hs
				}
				// 180s matches the WireGuard rekey interval + a keepalive
				// grace, same "fresh" threshold used by /api/vpn/peers.
				if now.Sub(p.LatestHshake) <= 3*time.Minute {
					block.ActivePeers++
				}
			}
			block.LastHandshake = latest
		}
		resp.VPN = block
	}

	// --- LAN routing snapshot -------------------------------------------
	// Guard with a closure so a panic inside lan.Manager (e.g. an unusual
	// iptables shell state) degrades just this block instead of killing
	// the whole request. Same pattern applied to USB/IP below.
	if h.lanMgr != nil {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Warn().Interface("panic", rec).Msg("system health: lan snapshot panicked")
					resp.Warnings = append(resp.Warnings, fmt.Sprintf("lan: %v", rec))
					resp.LAN = nil
				}
			}()
			live := h.lanMgr.Snapshot()
			routes := make([]healthLANRoute, 0, len(live))
			for _, r := range live {
				routes = append(routes, healthLANRoute{
					Subnet:  r.TargetSubnet,
					Applied: r.Applied,
				})
			}
			block := &healthLAN{
				Enabled:          len(live) > 0,
				Uplink:           h.lanMgr.Uplink(),
				Source:           h.lanMgr.Source(),
				IPForward:        lan.IPForwardEnabled(),
				Simulated:        h.lanMgr.Simulated(),
				Routes:           routes,
				ApplyErrorStreak: h.lanMgr.ApplyErrorStreak(),
				LastApplyError:   h.lanMgr.LastApplyError(),
			}
			if applied := h.lanMgr.LastAppliedAt(); !applied.IsZero() {
				ts := applied
				block.LastAppliedAt = &ts
			}
			resp.LAN = block
		}()
	}

	// --- USB/IP sessions + recent revocations ---------------------------
	if h.usbipH != nil {
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Warn().Interface("panic", rec).Msg("system health: usbip snapshot panicked")
					resp.Warnings = append(resp.Warnings, fmt.Sprintf("usbip: %v", rec))
					resp.USBIP = nil
				}
			}()
			block := &healthUSBIP{
				RecentRevocations: h.usbipH.RecentRevocations(10),
			}
			// Daemon "enabled" = config flag said so AND the daemon has a
			// running process. We can only observe the config reliably
			// from the handler's perspective via ExportedDevices — an
			// always-nil slice means we never started. To avoid guessing
			// we treat "exported slice non-nil" as the authoritative
			// signal, since ExportedDevices() on a non-started server
			// returns nil on unsupported platforms.
			if srv := h.usbipH.Server(); srv != nil {
				exported := srv.ExportedDevices()
				block.Enabled = exported != nil
				block.ExportedCount = len(exported)
			}
			// inUseCount: parse sysfs to count bus IDs with status==3
			// (SDEV_ST_USED_CONNECT — a remote client is attached). On
			// non-Linux platforms ListSessions returns (nil, nil) and
			// the count stays 0, which matches reality.
			if sessions, err := usblister.ListSessions(); err != nil {
				log.Warn().Err(err).Msg("system health: usbip list sessions failed")
				resp.Warnings = append(resp.Warnings, fmt.Sprintf("usbip sessions: %v", err))
			} else {
				for _, s := range sessions {
					if s.Status == 3 {
						block.InUseCount++
					}
				}
			}
			resp.USBIP = block
		}()
	}

	writeJSON(w, http.StatusOK, resp)
}
