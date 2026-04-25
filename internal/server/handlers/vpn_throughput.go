package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	wireguard "github.com/rud1-es/rud1-fw/internal/infrastructure/vpn"
)

// VPNThroughputHandler serves GET /api/vpn/throughput.
//
// Companion to iter 22's /api/vpn/peers/summary: that one returns
// handshake-shaped aggregates (counts, freshness, mean age); this one
// returns byte-shaped aggregates (cumulative bytesTx/bytesRx fleet-wide
// for the WG interface, plus per-peer breakdown when scoped to active
// peers in the window).
//
// WireGuard's kernel-side counters are cumulative since interface bring-
// up — there is no per-window subtotal exposed by `wg show dump`. So
// the `?window=` filter selects which peers count toward the per-window
// activeBytesTx/Rx totals (peers with a recent handshake) but the
// totalBytesTx/Rx fields always reflect the live cumulative value. This
// matches how the rest of the WG ecosystem (iperf, prom-exporters)
// surfaces transfer numbers.
type VPNThroughputHandler struct {
	iface   string
	peersFn func(iface string) ([]wireguard.RuntimePeer, error)
}

// NewVPNThroughputHandler wires the handler against the live WG iface.
// Empty iface is accepted (tests do it); production callers always pass
// the real wg0-equivalent.
func NewVPNThroughputHandler(iface string) *VPNThroughputHandler {
	return &VPNThroughputHandler{iface: iface, peersFn: wireguard.PeersForSummary}
}

// vpnThroughputResponse is the wire-format payload.
//
// All byte counters are uint64 to match the kernel-side ABI (32-bit
// would wrap on a busy peer in under a day on a fast LAN). TopPeers is
// length-capped at vpnThroughputTopPeersLimit so the response stays
// sub-kB even on a fleet of thousands of peers.
type vpnThroughputResponse struct {
	WindowSeconds      int64                  `json:"windowSeconds"`
	Now                int64                  `json:"now"`
	Interface          string                 `json:"interface"`
	PeerCount          int                    `json:"peerCount"`
	ActivePeerCount    int                    `json:"activePeerCount"`
	TotalBytesTx       uint64                 `json:"totalBytesTx"`
	TotalBytesRx       uint64                 `json:"totalBytesRx"`
	ActiveBytesTx      uint64                 `json:"activeBytesTx"`
	ActiveBytesRx      uint64                 `json:"activeBytesRx"`
	TopPeers           []vpnThroughputTopPeer `json:"topPeers"`
}

// vpnThroughputTopPeer is the per-peer slice of the throughput payload.
// Only peers with a non-zero combined transfer make the cut — a peer
// that has handshook but never moved data is uninteresting for a
// bandwidth dashboard.
type vpnThroughputTopPeer struct {
	PublicKey   string `json:"publicKey"`
	BytesTx     uint64 `json:"bytesTx"`
	BytesRx     uint64 `json:"bytesRx"`
	TotalBytes  uint64 `json:"totalBytes"`
}

// Same enumerated set as iter 22's /summary — strict-parse for the same
// reason (the dashboard offers four buttons; a stray window= is a
// client bug, not something to silently clamp).
var vpnThroughputWindows = map[string]time.Duration{
	"1h":  1 * time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
}

const (
	vpnThroughputDefaultWindow = 24 * time.Hour
	// vpnThroughputTopPeersLimit caps the per-peer slice length. A
	// dashboard tile rarely needs more than the top 5; matching the
	// FleetReboots tile's "5 worst offenders" pattern from iter 22.
	vpnThroughputTopPeersLimit = 5
)

// Throughput handles GET /api/vpn/throughput.
//
// Query params:
//
//	window — one of 1h, 6h, 24h, 7d. Default 24h when missing. Any
//	         other value is rejected with 400 (no silent clamping —
//	         matches /summary's strict-parse).
//
// Responses:
//
//	200 — vpnThroughputResponse with cumulative + windowed aggregates.
//	400 — unrecognized window value.
//	500 — wg enumeration failed.
//	503 — platform doesn't support WireGuard.
func (h *VPNThroughputHandler) Throughput(w http.ResponseWriter, r *http.Request) {
	window, ok := parseVPNThroughputWindow(r.URL.Query().Get("window"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid window (expected 1h, 6h, 24h, or 7d)")
		return
	}

	peers, err := h.peersFn(h.iface)
	if err != nil {
		if errors.Is(err, wireguard.ErrVPNUnsupported) {
			writeError(w, http.StatusServiceUnavailable, "vpn throughput unavailable on this platform")
			return
		}
		log.Warn().Err(err).Str("iface", h.iface).Msg("vpn throughput: list failed")
		writeError(w, http.StatusInternalServerError, "failed to list WireGuard peers")
		return
	}

	now := time.Now().UTC()
	cutoff := now.Add(-window)

	var (
		totalTx, totalRx   uint64
		activeTx, activeRx uint64
		activeCount        int
	)
	candidates := make([]vpnThroughputTopPeer, 0, len(peers))
	for _, p := range peers {
		totalTx += p.BytesTx
		totalRx += p.BytesRx

		if !p.LatestHshake.IsZero() && p.LatestHshake.After(cutoff) {
			activeTx += p.BytesTx
			activeRx += p.BytesRx
			activeCount++
		}

		// Peers with zero combined transfer are skipped from the top-N
		// candidate set — a freshly-added peer that hasn't moved bytes
		// yet would otherwise occupy a slot ahead of one that has.
		combined := p.BytesTx + p.BytesRx
		if combined == 0 {
			continue
		}
		candidates = append(candidates, vpnThroughputTopPeer{
			PublicKey:  p.PublicKey,
			BytesTx:    p.BytesTx,
			BytesRx:    p.BytesRx,
			TotalBytes: combined,
		})
	}

	// Insertion-sort the candidates descending by combined transfer.
	// O(n²) but n ≤ peer count which is bounded in the low hundreds on
	// a Pi-class device — cheaper than pulling in sort.Slice for a
	// single call.
	for i := 1; i < len(candidates); i++ {
		for j := i; j > 0 && candidates[j].TotalBytes > candidates[j-1].TotalBytes; j-- {
			candidates[j], candidates[j-1] = candidates[j-1], candidates[j]
		}
	}
	if len(candidates) > vpnThroughputTopPeersLimit {
		candidates = candidates[:vpnThroughputTopPeersLimit]
	}

	writeJSON(w, http.StatusOK, vpnThroughputResponse{
		WindowSeconds:   int64(window.Seconds()),
		Now:             now.Unix(),
		Interface:       h.iface,
		PeerCount:       len(peers),
		ActivePeerCount: activeCount,
		TotalBytesTx:    totalTx,
		TotalBytesRx:    totalRx,
		ActiveBytesTx:   activeTx,
		ActiveBytesRx:   activeRx,
		TopPeers:        candidates,
	})
}

// parseVPNThroughputWindow resolves `?window=` against the enumerated
// set. Empty defaults to 24h; anything outside the set returns
// (0, false) so the handler can emit a 400. Mirrors the equivalent
// parser in vpn_peers_summary.go — kept separate (rather than shared)
// so the two endpoints can diverge in the future without breaking
// each other's tests.
func parseVPNThroughputWindow(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return vpnThroughputDefaultWindow, true
	}
	if d, ok := vpnThroughputWindows[strings.ToLower(raw)]; ok {
		return d, true
	}
	return 0, false
}
