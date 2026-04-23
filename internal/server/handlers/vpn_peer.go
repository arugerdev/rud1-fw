package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	wireguard "github.com/rud1-es/rud1-fw/internal/infrastructure/vpn"
)

// VPNPeerHandler exposes direct control over the WireGuard server's client
// peers, independent of the cloud-driven heartbeat sync.
//
// The cloud path (heartbeat response → applyClientPeers) is the source of
// truth for peers that belong to users claimed against this device's
// organization. This local handler is the operator/out-of-band escape
// hatch: rud1-app uses it to display the live peer table; a disconnected-
// cloud install can still add a temporary peer by pasting its pubkey.
//
// NOTE: peers added via POST here are NOT persisted across wg-quick
// restarts — the underlying `wg set` lives in the kernel, not in the
// YAML-backed config file. This matches how the cloud-driven sync works
// and is by design: the cloud re-pushes the authoritative set on every
// heartbeat, so the interface converges quickly after any restart.
type VPNPeerHandler struct {
	iface string
}

// NewVPNPeerHandler wires a handler against the given WireGuard interface.
func NewVPNPeerHandler(iface string) *VPNPeerHandler {
	return &VPNPeerHandler{iface: iface}
}

type peerListItem struct {
	PublicKey           string `json:"publicKey"`
	AllowedIPs          string `json:"allowedIps"`
	Endpoint            string `json:"endpoint,omitempty"`
	LastHandshake       int64  `json:"lastHandshake"` // unix seconds; 0 = never
	BytesRx             uint64 `json:"bytesRx"`
	BytesTx             uint64 `json:"bytesTx"`
	PersistentKeepalive int    `json:"persistentKeepalive,omitempty"`
}

type peerListResponse struct {
	Interface string         `json:"interface"`
	Peers     []peerListItem `json:"peers"`
	Now       int64          `json:"now"`
	// ActiveCount is the number of peers with a handshake within the
	// last 3 minutes — the conventional WireGuard "fresh" threshold
	// (PersistentKeepalive defaults to 25s, and rekeys fire at 120s).
	ActiveCount int `json:"activeCount"`
}

// List handles GET /api/vpn/peers — returns the live peer set on the server.
// Useful for rud1-app's VpnPanel to render the list of currently-connected
// clients with their last-handshake freshness.
func (h *VPNPeerHandler) List(w http.ResponseWriter, r *http.Request) {
	live, err := wireguard.ListPeers(h.iface)
	if err != nil {
		log.Warn().Err(err).Msg("vpn peers: list failed")
		writeError(w, http.StatusInternalServerError, "failed to list WireGuard peers")
		return
	}
	now := time.Now()
	items := make([]peerListItem, 0, len(live))
	activeCount := 0
	for _, p := range live {
		var hs int64
		if !p.LatestHshake.IsZero() {
			hs = p.LatestHshake.Unix()
			if now.Sub(p.LatestHshake) <= 3*time.Minute {
				activeCount++
			}
		}
		items = append(items, peerListItem{
			PublicKey:           p.PublicKey,
			AllowedIPs:          p.AllowedIPs,
			Endpoint:            p.Endpoint,
			LastHandshake:       hs,
			BytesRx:             p.BytesRx,
			BytesTx:             p.BytesTx,
			PersistentKeepalive: p.PersistentKeepalive,
		})
	}
	writeJSON(w, http.StatusOK, peerListResponse{
		Interface:   h.iface,
		Peers:       items,
		Now:         now.Unix(),
		ActiveCount: activeCount,
	})
}

type addPeerRequest struct {
	PublicKey           string `json:"publicKey"`
	AllowedIPs          string `json:"allowedIps"`
	PersistentKeepalive int    `json:"persistentKeepalive,omitempty"`
}

// Add handles POST /api/vpn/peers — installs a single [Peer] on the live
// interface. The kernel treats the call as idempotent: re-POSTing the same
// pubkey+allowed-ips is a no-op.
func (h *VPNPeerHandler) Add(w http.ResponseWriter, r *http.Request) {
	var req addPeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	req.AllowedIPs = strings.TrimSpace(req.AllowedIPs)
	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "publicKey is required")
		return
	}
	if req.AllowedIPs == "" {
		writeError(w, http.StatusBadRequest, "allowedIps is required")
		return
	}
	if err := wireguard.AddPeer(h.iface, req.PublicKey, req.AllowedIPs, req.PersistentKeepalive); err != nil {
		log.Error().Err(err).Str("pubkey", req.PublicKey).Msg("vpn peers: add failed")
		writeError(w, http.StatusInternalServerError, "failed to add peer")
		return
	}
	log.Info().
		Str("iface", h.iface).
		Str("pubkey", req.PublicKey).
		Str("allowed_ips", req.AllowedIPs).
		Msg("vpn peers: added")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                  true,
		"publicKey":           req.PublicKey,
		"allowedIps":          req.AllowedIPs,
		"persistentKeepalive": req.PersistentKeepalive,
	})
}

// Remove handles DELETE /api/vpn/peers?publicKey=<pubkey> — drops the peer
// from the live interface. Safe on a pubkey the interface doesn't know.
func (h *VPNPeerHandler) Remove(w http.ResponseWriter, r *http.Request) {
	pubkey := strings.TrimSpace(r.URL.Query().Get("publicKey"))
	if pubkey == "" {
		writeError(w, http.StatusBadRequest, "publicKey query parameter is required")
		return
	}
	if err := wireguard.RemovePeer(h.iface, pubkey); err != nil {
		log.Error().Err(err).Str("pubkey", pubkey).Msg("vpn peers: remove failed")
		writeError(w, http.StatusInternalServerError, "failed to remove peer")
		return
	}
	log.Info().Str("iface", h.iface).Str("pubkey", pubkey).Msg("vpn peers: removed")
	w.WriteHeader(http.StatusNoContent)
}
