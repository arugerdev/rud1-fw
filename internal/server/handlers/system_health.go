package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/sysstat"
	wireguard "github.com/rud1-es/rud1-fw/internal/infrastructure/vpn"
)

// SystemHealthHandler serves GET /api/system/health — a consolidated
// diagnostic snapshot combining sysstat metrics (+ rolling percentiles)
// and WireGuard peer summary in a single call. Intended for dashboards
// and probes that want one round-trip instead of hitting /api/system/stats
// and /api/vpn/peers separately.
//
// The handler is read-only and degrades gracefully: if a sub-collector
// fails we log the error and omit/null that section rather than 500.
type SystemHealthHandler struct {
	collector *sysstat.Collector
	iface     string
}

// NewSystemHealthHandler wires the handler against the shared sysstat
// collector and the WireGuard interface name read from cfg.VPN.Interface.
func NewSystemHealthHandler(collector *sysstat.Collector, iface string) *SystemHealthHandler {
	return &SystemHealthHandler{collector: collector, iface: iface}
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

// systemHealthResponse is the JSON payload served by Health.
// System / Percentiles / VPN are nullable so a partial failure (e.g.
// `wg show` missing on a dev box) still produces a structurally valid
// response the client can parse.
type systemHealthResponse struct {
	Timestamp   int64                          `json:"timestamp"`
	System      *sysstat.Stats                 `json:"system"`
	Percentiles *sysstat.PercentilesSnapshot   `json:"percentiles"`
	VPN         *vpnHealthBlock                `json:"vpn"`
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

	writeJSON(w, http.StatusOK, resp)
}
