package handlers

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/nat"
	wireguard "github.com/rud1-es/rud1-fw/internal/infrastructure/vpn"
	"github.com/rud1-es/rud1-fw/internal/platform"
)

// NatSnapshot is a callback the agent provides so this handler can surface
// the most recent NAT discovery (public endpoint, UPnP state, NAT type)
// without the handler having to own the discovery loop. Returning the zero
// value is safe — the handler treats empty fields as "not discovered yet".
type NatSnapshot func() nat.Discovery

// VPNHandler serves VPN-related API endpoints.
type VPNHandler struct {
	configPath    string
	iface         string
	ownPubkeyPath string
	natSnapshot   NatSnapshot // may be nil in legacy wiring
}

// NewVPNHandler creates a VPNHandler for the given WireGuard config file and
// interface name. ownPubkeyPath points at the world-readable mirror of the
// device's own WG public key. `natSnap` is optional — when nil the handler
// omits the NAT-related response fields.
func NewVPNHandler(configPath, iface, ownPubkeyPath string, natSnap NatSnapshot) *VPNHandler {
	return &VPNHandler{
		configPath:    configPath,
		iface:         iface,
		ownPubkeyPath: ownPubkeyPath,
		natSnapshot:   natSnap,
	}
}

// vpnStatusResponse is the payload returned by GET /api/vpn/status.
//
// Post-2026-04-22 (no hub) semantics:
//   - publicKey      → the device's own WG server pubkey (also = ownPublicKey,
//                      kept as an alias for legacy UI consumers).
//   - publicEndpoint → the router-visible "host:port" the agent discovered.
//   - upnpOk         → true iff UPnP/NAT-PMP mapped the port successfully.
//   - natType        → "open" | "restricted" | "symmetric" | "unknown".
//   - natSource      → which discovery path produced the endpoint.
type vpnStatusResponse struct {
	Interface      string `json:"interface"`
	Connected      bool   `json:"connected"`
	Address        string `json:"address"`
	DNS            string `json:"dns"`
	Endpoint       string `json:"endpoint"`
	AllowedIPs     string `json:"allowedIPs"`
	PublicKey      string `json:"publicKey"`
	OwnPublicKey   string `json:"ownPublicKey,omitempty"`
	LastHandshake  int64  `json:"lastHandshake"`
	PublicEndpoint string `json:"publicEndpoint,omitempty"`
	UPnPOK         bool   `json:"upnpOk"`
	NATType        string `json:"natType,omitempty"`
	NATSource      string `json:"natSource,omitempty"`
	// CGNAT is true when the discovered public endpoint falls inside the
	// RFC 6598 carrier-grade NAT range (100.64.0.0/10). The local panel
	// surfaces an actionable warning when set, since direct WG from
	// CGNAT'd uplinks is not feasible without IPv6 or a relay.
	CGNAT          bool   `json:"cgnat"`
}

// Status handles GET /api/vpn/status.
func (h *VPNHandler) Status(w http.ResponseWriter, r *http.Request) {
	ownPubkey := h.readOwnPubkey()

	// Fetch NAT snapshot up-front so both the happy-path and the "no config
	// file yet" branch can populate the response.
	var natSnap nat.Discovery
	if h.natSnapshot != nil {
		natSnap = h.natSnapshot()
	}

	st, err := wireguard.Read(h.configPath)
	if err != nil {
		log.Warn().Err(err).Str("path", h.configPath).Msg("could not read wireguard config")
		writeJSON(w, http.StatusOK, vpnStatusResponse{
			Interface:      h.iface,
			Connected:      wireguard.IsConnected(h.iface),
			PublicKey:      ownPubkey, // no hub — our own key is the peer ref.
			OwnPublicKey:   ownPubkey,
			PublicEndpoint: natSnap.PublicEndpoint,
			UPnPOK:         natSnap.UPnPOK,
			NATType:        natSnap.NATType,
			NATSource:      natSnap.Source,
			CGNAT:          natSnap.CGNAT,
		})
		return
	}

	var handshake int64
	if st.Connected {
		if ts, err := wireguard.LatestHandshake(st.Interface); err == nil && !ts.IsZero() {
			handshake = ts.Unix()
		}
	}

	writeJSON(w, http.StatusOK, vpnStatusResponse{
		Interface:      st.Interface,
		Connected:      st.Connected,
		Address:        st.Address,
		DNS:            st.DNS,
		// Prefer the NAT-discovered endpoint over whatever might be
		// written in the config. Falls back to st.Endpoint only if the
		// discovery hasn't populated yet.
		Endpoint:       firstNonEmpty(natSnap.PublicEndpoint, st.Endpoint),
		AllowedIPs:     st.AllowedIPs,
		PublicKey:      firstNonEmpty(ownPubkey, st.PublicKey),
		OwnPublicKey:   ownPubkey,
		LastHandshake:  handshake,
		PublicEndpoint: natSnap.PublicEndpoint,
		UPnPOK:         natSnap.UPnPOK,
		NATType:        natSnap.NATType,
		NATSource:      natSnap.Source,
		CGNAT:          natSnap.CGNAT,
	})
}

func firstNonEmpty(candidates ...string) string {
	for _, c := range candidates {
		if c != "" {
			return c
		}
	}
	return ""
}

func (h *VPNHandler) readOwnPubkey() string {
	if h.ownPubkeyPath == "" {
		return ""
	}
	key, err := wireguard.ReadOwnPubkey(h.ownPubkeyPath)
	if err != nil {
		return ""
	}
	return key
}

// Reconnect handles POST /api/vpn/reconnect.
func (h *VPNHandler) Reconnect(w http.ResponseWriter, r *http.Request) {
	if platform.SimulateHardware() {
		log.Info().Msg("vpn reconnect requested (simulated — no-op)")
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	log.Info().Str("iface", h.iface).Msg("vpn reconnect: bringing interface down")
	down := exec.CommandContext(r.Context(), "wg-quick", "down", h.iface)
	if err := down.Run(); err != nil {
		log.Warn().Err(err).Msg("wg-quick down failed (may be already down)")
	}

	log.Info().Str("iface", h.iface).Msg("vpn reconnect: bringing interface up")
	up := exec.CommandContext(r.Context(), "wg-quick", "up", h.iface)
	if err := up.Run(); err != nil {
		log.Error().Err(err).Msg("wg-quick up failed")
		writeError(w, http.StatusInternalServerError, "failed to bring VPN interface up")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// vpnConfigRequest is the body accepted by POST /api/vpn/config.
// rud1-es posts this after the device registers to push WireGuard settings.
type vpnConfigRequest struct {
	PrivateKey string `json:"privateKey"`
	Address    string `json:"address"`
	DNS        string `json:"dns"`
	PublicKey  string `json:"peerPublicKey"`  // peer public key
	Endpoint   string `json:"endpoint"`
	AllowedIPs string `json:"allowedIPs"`
}

// ApplyConfig handles POST /api/vpn/config.
// It writes the received WireGuard config to disk and optionally brings the
// interface up (Linux only).
func (h *VPNHandler) ApplyConfig(w http.ResponseWriter, r *http.Request) {
	var req vpnConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	cfg := &wireguard.Status{
		PrivateKey: req.PrivateKey,
		Address:    req.Address,
		DNS:        req.DNS,
		PublicKey:  req.PublicKey,
		Endpoint:   req.Endpoint,
		AllowedIPs: req.AllowedIPs,
	}

	if err := wireguard.Write(h.configPath, cfg); err != nil {
		log.Error().Err(err).Msg("failed to write vpn config")
		writeError(w, http.StatusInternalServerError, "failed to write VPN config")
		return
	}

	log.Info().
		Str("address", req.Address).
		Str("endpoint", req.Endpoint).
		Msg("VPN config applied")

	// On Linux, bring the interface up/down to apply the new config.
	if !platform.SimulateHardware() {
		_ = exec.Command("wg-quick", "down", h.iface).Run()
		if err := exec.Command("wg-quick", "up", h.iface).Run(); err != nil {
			log.Warn().Err(err).Msg("wg-quick up failed after config apply")
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "applied"})
}
