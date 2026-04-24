package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	wireguard "github.com/rud1-es/rud1-fw/internal/infrastructure/vpn"
)

// VPNPeersSummaryHandler serves GET /api/vpn/peers/summary.
//
// Mirrors iter 19's /api/system/uptime-summary: rud1-app otherwise has to
// pull the full /api/vpn/peers list and reduce it client-side on every
// dashboard tick, which is wasteful over the tunnel and on battery-powered
// clients. This endpoint precomputes the tile-ready aggregates (counts,
// mean handshake age, last-active peer) so the mobile panel can render the
// VPN card with a single GET.
//
// The handler is stateless — it shells out to wg on each call via the
// injected peersFn. That's the same model used by the live VPNPeerHandler;
// there's no per-peer history kept in memory. The indirection through a
// function (rather than calling wireguard.PeersForSummary directly) keeps
// the handler unit-testable without a live WG interface.
type VPNPeersSummaryHandler struct {
	iface   string
	peersFn func(iface string) ([]wireguard.RuntimePeer, error)
}

// NewVPNPeersSummaryHandler wires a handler against the given WireGuard
// interface name. Empty iface is accepted (callers do it in unit tests)
// but every production wiring passes the real wg0-equivalent.
func NewVPNPeersSummaryHandler(iface string) *VPNPeersSummaryHandler {
	return &VPNPeersSummaryHandler{iface: iface, peersFn: wireguard.PeersForSummary}
}

// vpnPeersSummaryResponse is the wire-format payload.
//
// Nullable fields use pointers so JSON emits `null` rather than a
// misleading `0`/empty-string when the underlying quantity is undefined
// (e.g. no peers have ever handshook → meanHandshakeAgeSeconds must be
// null, not 0).
type vpnPeersSummaryResponse struct {
	WindowSeconds           int64   `json:"windowSeconds"`
	Now                     int64   `json:"now"`
	Interface               string  `json:"interface"`
	PeerCount               int     `json:"peerCount"`
	TotalHandshakes         int     `json:"totalHandshakes"`
	MeanHandshakeAgeSeconds *int64  `json:"meanHandshakeAgeSeconds"`
	StaleCount              int     `json:"staleCount"`
	FreshCount              int     `json:"freshCount"`
	NeverCount              int     `json:"neverCount"`
	LastActivePeer          *string `json:"lastActivePeer"`
}

// Accepted window values. Unlike iter 19's uptime-summary (which clamps
// silently), this endpoint rejects anything outside the short enumerated
// set with a 400 — dashboards are expected to pick one of four buckets,
// and silently rewriting a caller's intent to "24h" when they asked for
// "5m" would mask client bugs. Ordering mirrors the UI toggle: shortest
// first.
var vpnPeersSummaryWindows = map[string]time.Duration{
	"1h":  1 * time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
}

// vpnPeersSummaryDefaultWindow matches the most common dashboard view and
// caps the default at a day so an unspecified `window=` won't ever scan
// more than the week ceiling's worth.
const vpnPeersSummaryDefaultWindow = 24 * time.Hour

// vpnPeersFreshThreshold — the conventional WireGuard "fresh" cutoff
// (PersistentKeepalive defaults to 25s, rekeys fire at 120s, so 3min
// comfortably covers both). Matches the same threshold used by
// VPNPeerHandler.List's ActiveCount.
const vpnPeersFreshThreshold = 3 * time.Minute

// Summary handles GET /api/vpn/peers/summary.
//
// Query params:
//
//	window — one of 1h, 6h, 24h, 7d. Default 24h when missing. Any other
//	         value is rejected with 400 (no silent clamping).
//
// Responses:
//
//	200 — `{windowSeconds, now, interface, peerCount, totalHandshakes,
//	        meanHandshakeAgeSeconds, staleCount, freshCount, neverCount,
//	        lastActivePeer}`.
//	400 — unrecognized window value.
//	500 — wg enumeration failed (binary missing, iface down, etc.).
//	503 — platform doesn't support WireGuard (e.g. Windows dev machine
//	      with a real config pointed at it).
func (h *VPNPeersSummaryHandler) Summary(w http.ResponseWriter, r *http.Request) {
	window, ok := parseVPNPeersSummaryWindow(r.URL.Query().Get("window"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid window (expected 1h, 6h, 24h, or 7d)")
		return
	}

	peers, err := h.peersFn(h.iface)
	if err != nil {
		if errors.Is(err, wireguard.ErrVPNUnsupported) {
			writeError(w, http.StatusServiceUnavailable, "vpn peers summary unavailable on this platform")
			return
		}
		log.Warn().Err(err).Str("iface", h.iface).Msg("vpn peers summary: list failed")
		writeError(w, http.StatusInternalServerError, "failed to list WireGuard peers")
		return
	}

	now := time.Now().UTC()
	cutoff := now.Add(-window)

	var (
		totalHandshakes int
		staleCount      int
		freshCount      int
		neverCount      int
		ageSum          time.Duration
		ageSamples      int
		lastPeer        *string
		lastAt          time.Time
	)
	for _, p := range peers {
		if p.LatestHshake.IsZero() {
			neverCount++
			continue
		}
		age := now.Sub(p.LatestHshake)
		ageSum += age
		ageSamples++

		// A peer is "active in the window" iff its latest handshake is
		// not older than the window cutoff. WireGuard only exposes the
		// latest handshake per peer (not a history), so this equals
		// "peers that handshook at least once inside the window".
		if p.LatestHshake.After(cutoff) {
			totalHandshakes++
		}

		if age <= vpnPeersFreshThreshold {
			freshCount++
		} else {
			staleCount++
		}

		if lastPeer == nil || p.LatestHshake.After(lastAt) {
			pk := p.PublicKey
			lastPeer = &pk
			lastAt = p.LatestHshake
		}
	}

	// meanHandshakeAgeSeconds across peers that have ever handshook.
	// Null when every peer is in the "never" bucket (same rationale as
	// iter 19's cleanShutdownRatio: the dashboard renders "—" rather
	// than a misleading "0s since last handshake").
	var meanAge *int64
	if ageSamples > 0 {
		v := int64(ageSum.Seconds()) / int64(ageSamples)
		meanAge = &v
	}

	writeJSON(w, http.StatusOK, vpnPeersSummaryResponse{
		WindowSeconds:           int64(window.Seconds()),
		Now:                     now.Unix(),
		Interface:               h.iface,
		PeerCount:               len(peers),
		TotalHandshakes:         totalHandshakes,
		MeanHandshakeAgeSeconds: meanAge,
		StaleCount:              staleCount,
		FreshCount:              freshCount,
		NeverCount:              neverCount,
		LastActivePeer:          lastPeer,
	})
}

// parseVPNPeersSummaryWindow resolves the `?window=` query against the
// enumerated set. Empty string defaults to 24h (the most common dashboard
// bucket); anything else is matched case-insensitively against
// vpnPeersSummaryWindows. The bool return distinguishes "missing/default"
// from "explicitly rejected" — callers surface the latter as a 400. Kept
// deliberately stricter than iter 19's parseUptimeSummaryWindow: the VPN
// dashboard's window toggle only renders four buttons, so silently
// clamping a stray value masks client-side bugs.
func parseVPNPeersSummaryWindow(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return vpnPeersSummaryDefaultWindow, true
	}
	if d, ok := vpnPeersSummaryWindows[strings.ToLower(raw)]; ok {
		return d, true
	}
	return 0, false
}
