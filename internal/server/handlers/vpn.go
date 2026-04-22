package handlers

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"time"

	"github.com/rs/zerolog/log"

	wireguard "github.com/rud1-es/rud1-fw/internal/infrastructure/vpn"
	"github.com/rud1-es/rud1-fw/internal/platform"
)

// VPNHandler serves VPN-related API endpoints.
type VPNHandler struct {
	configPath    string
	iface         string
	ownPubkeyPath string
}

// NewVPNHandler creates a VPNHandler for the given WireGuard config file and
// interface name. ownPubkeyPath points at the world-readable mirror of the
// device's own WG public key (see VPNConfig.PubkeyPath) — may be empty on
// older deployments, in which case the `ownPublicKey` field is omitted.
func NewVPNHandler(configPath, iface, ownPubkeyPath string) *VPNHandler {
	return &VPNHandler{configPath: configPath, iface: iface, ownPubkeyPath: ownPubkeyPath}
}

// vpnStatusResponse is the payload returned by GET /api/vpn/status.
//
// `publicKey` is the [Peer] pubkey (the hub's) parsed from wg0.conf.
// `ownPublicKey` is the DEVICE's own pubkey — useful for the local panel to
// display the identity this device advertises to the cloud.
// `lastHandshake` is the most recent handshake across peers as unix seconds,
// 0 when the device has never handshaked (or hardware is simulated).
type vpnStatusResponse struct {
	Interface     string `json:"interface"`
	Connected     bool   `json:"connected"`
	Address       string `json:"address"`
	DNS           string `json:"dns"`
	Endpoint      string `json:"endpoint"`
	AllowedIPs    string `json:"allowedIPs"`
	PublicKey     string `json:"publicKey"`
	OwnPublicKey  string `json:"ownPublicKey,omitempty"`
	LastHandshake int64  `json:"lastHandshake"`
}

// Status handles GET /api/vpn/status.
func (h *VPNHandler) Status(w http.ResponseWriter, r *http.Request) {
	ownPubkey := h.readOwnPubkey()

	st, err := wireguard.Read(h.configPath)
	if err != nil {
		log.Warn().Err(err).Str("path", h.configPath).Msg("could not read wireguard config")
		// Return a minimal status rather than erroring when the file simply doesn't exist yet.
		writeJSON(w, http.StatusOK, vpnStatusResponse{
			Interface:    h.iface,
			Connected:    wireguard.IsConnected(h.iface),
			OwnPublicKey: ownPubkey,
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
		Interface:     st.Interface,
		Connected:     st.Connected,
		Address:       st.Address,
		DNS:           st.DNS,
		Endpoint:      st.Endpoint,
		AllowedIPs:    st.AllowedIPs,
		PublicKey:     st.PublicKey,
		OwnPublicKey:  ownPubkey,
		LastHandshake: handshake,
	})
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
