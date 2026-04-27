package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
	cx "github.com/rud1-es/rud1-fw/internal/domain/connectivity"
)

// ConnectivityHandler serves WiFi / cellular / AP management endpoints.
type ConnectivityHandler struct {
	svc cx.Service
	cfg *config.Config
	// apMu serialises AP-credentials mutations so a flaky panel that
	// double-submits doesn't interleave config writes (Save() is itself
	// atomic but we want the in-memory snapshot to match disk).
	apMu sync.Mutex
}

// NewConnectivityHandler constructs a handler around a Service.
//
// cfg is required for endpoints that persist mutations to config.yaml
// (e.g. PUT /api/network/ap/credentials). May be nil in tests that don't
// exercise the persistence path.
func NewConnectivityHandler(svc cx.Service, cfg *config.Config) *ConnectivityHandler {
	return &ConnectivityHandler{svc: svc, cfg: cfg}
}

// Snapshot — GET /api/network/connectivity
func (h *ConnectivityHandler) Snapshot(w http.ResponseWriter, r *http.Request) {
	snap, err := h.svc.Snapshot(r.Context())
	if err != nil {
		log.Warn().Err(err).Msg("connectivity snapshot failed")
		writeError(w, http.StatusInternalServerError, "snapshot failed")
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// SetPreferred — POST /api/network/connectivity/preferred {preferred}
func (h *ConnectivityHandler) SetPreferred(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Preferred cx.Preferred `json:"preferred"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := h.svc.SetPreferred(r.Context(), body.Preferred); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "preferred": body.Preferred})
}

// ── WiFi ────────────────────────────────────────────────────────────────────

// WiFiScan — GET /api/network/wifi/scan
func (h *ConnectivityHandler) WiFiScan(w http.ResponseWriter, r *http.Request) {
	nets, err := h.svc.WiFiScan(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"networks": nets})
}

// WiFiSaved — GET /api/network/wifi/saved
func (h *ConnectivityHandler) WiFiSaved(w http.ResponseWriter, r *http.Request) {
	saved, err := h.svc.WiFiSaved(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": saved})
}

// WiFiStatus — GET /api/network/wifi/status
func (h *ConnectivityHandler) WiFiStatus(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.WiFiStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// WiFiConnect — POST /api/network/wifi/connect
func (h *ConnectivityHandler) WiFiConnect(w http.ResponseWriter, r *http.Request) {
	var req cx.ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	// Do NOT TrimSpace the SSID. 802.11 SSIDs are 0..32 arbitrary bytes and
	// may legitimately begin or end with whitespace — iPhone Personal
	// Hotspots, for instance, broadcast the device name verbatim ("Alvaritoru ")
	// and trimming silently mangles it so nmcli can't find the AP.
	if req.SSID == "" {
		writeError(w, http.StatusBadRequest, "ssid is required")
		return
	}
	if err := h.svc.WiFiConnect(r.Context(), req); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// WiFiDisconnect — POST /api/network/wifi/disconnect
func (h *ConnectivityHandler) WiFiDisconnect(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.WiFiDisconnect(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// WiFiForget — DELETE /api/network/wifi/saved/{ssid}
func (h *ConnectivityHandler) WiFiForget(w http.ResponseWriter, r *http.Request) {
	ssid := chi.URLParam(r, "ssid")
	if ssid == "" {
		writeError(w, http.StatusBadRequest, "ssid required")
		return
	}
	if err := h.svc.WiFiForget(r.Context(), ssid); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ── Cellular ────────────────────────────────────────────────────────────────

// CellularStatus — GET /api/network/cellular
func (h *ConnectivityHandler) CellularStatus(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.CellularStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// CellularSetConfig — POST /api/network/cellular/config
func (h *ConnectivityHandler) CellularSetConfig(w http.ResponseWriter, r *http.Request) {
	var cfg cx.CellularConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := h.svc.CellularSetConfig(r.Context(), cfg); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// CellularUnlockPIN — POST /api/network/cellular/pin
func (h *ConnectivityHandler) CellularUnlockPIN(w http.ResponseWriter, r *http.Request) {
	var body cx.PINRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := h.svc.CellularUnlockPIN(r.Context(), body.PIN); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// CellularConnect — POST /api/network/cellular/connect
func (h *ConnectivityHandler) CellularConnect(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.CellularConnect(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// CellularDisconnect — POST /api/network/cellular/disconnect
func (h *ConnectivityHandler) CellularDisconnect(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.CellularDisconnect(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ── AP ──────────────────────────────────────────────────────────────────────

// APStatus — GET /api/network/ap
func (h *ConnectivityHandler) APStatus(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.APStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// APSet — POST /api/network/ap  {enabled}
func (h *ConnectivityHandler) APSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	var err error
	if body.Enabled {
		err = h.svc.APEnable(r.Context())
	} else {
		err = h.svc.APDisable(r.Context())
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": body.Enabled})
}

// APSetCredentials — PUT /api/network/ap/credentials  {ssid?, password}
//
// Mutates the SSID/password the setup hotspot will use. Persisted to
// config.yaml so the change survives a reboot, and applied in-place when
// the AP is currently active so the operator sees the new credentials
// without needing to restart the agent.
//
// The factory default password ("configurame") is uniform across the
// fleet — this endpoint is the supported way for an operator to rotate
// it once the device is in production.
func (h *ConnectivityHandler) APSetCredentials(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SSID     string `json:"ssid"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	ssid := strings.TrimSpace(body.SSID)
	pass := body.Password // do NOT trim — trailing/leading spaces are valid PSK chars
	if len(pass) < 8 || len(pass) > 63 {
		writeError(w, http.StatusBadRequest, "password length must be between 8 and 63 characters (WPA2-PSK)")
		return
	}
	if n := len(ssid); n > 32 {
		// IEEE 802.11 SSID length cap (32 octets).
		writeError(w, http.StatusBadRequest, "ssid length must be at most 32 characters")
		return
	}
	if h.cfg == nil {
		// Tests that wire a handler without a config still get a usable
		// path through the service for runtime mutation; we just can't
		// persist. Keeping this branch lets `go test` exercise the
		// handler without faking a YAML-on-disk.
		if err := h.svc.APSetCredentials(r.Context(), ssid, pass); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	h.apMu.Lock()
	defer h.apMu.Unlock()

	prevSSID := h.cfg.Network.APSSID
	prevPass := h.cfg.Network.APPassword
	if ssid != "" {
		h.cfg.Network.APSSID = ssid
	}
	h.cfg.Network.APPassword = pass

	if err := h.cfg.Save(); err != nil {
		// Roll back the in-memory mutation so the next read reflects disk.
		h.cfg.Network.APSSID = prevSSID
		h.cfg.Network.APPassword = prevPass
		log.Warn().Err(err).Msg("ap: persist credentials failed")
		writeError(w, http.StatusInternalServerError, "failed to persist ap credentials")
		return
	}

	// Apply in-memory + recycle the AP if active. We've already persisted,
	// so a service-level error here is a soft failure (the change WILL
	// take effect on the next agent restart).
	if err := h.svc.APSetCredentials(r.Context(), ssid, pass); err != nil {
		log.Warn().Err(err).Msg("ap: hot-apply credentials failed (will take effect on next restart)")
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"applied": false,
			"warning": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "applied": true})
}
