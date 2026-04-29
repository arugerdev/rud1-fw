package handlers

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/serbridge"
	usblister "github.com/rud1-es/rud1-fw/internal/infrastructure/usb"
)

// SerialBridgeHandler exposes the TCP↔serial proxy to the local HTTP
// API. The client-facing surface mirrors the USB/IP handler shape
// (status / sessions / open / close) so the desktop bridge can switch
// transports with a one-line change in its router. Authorization
// shares the same authorized_nets allowlist as USB/IP — most installs
// want both transports gated by the same VPN-subnet rule.
type SerialBridgeHandler struct {
	mgr serbridge.Manager
	cfg *config.USBConfig
}

// NewSerialBridgeHandler returns a handler bound to the manager and
// USB config. Both pointers are non-nil callsite invariants — passing
// nil would crash on the first request, but the agent bootstrap
// fast-fails earlier so a misconfigured deploy never gets here.
func NewSerialBridgeHandler(mgr serbridge.Manager, cfg *config.USBConfig) *SerialBridgeHandler {
	return &SerialBridgeHandler{mgr: mgr, cfg: cfg}
}

// isAuthorized mirrors USBIPHandler.isAuthorized so both transports
// gate on the same allowlist by default. SerialBridge.AuthorizedNets,
// when set, takes precedence — operators with stricter compliance
// requirements (a tenant that only wants serial bridge over relay,
// not direct WG) can lock the bridge port to a tighter CIDR than
// the USB/IP listener.
func (h *SerialBridgeHandler) isAuthorized(r *http.Request) bool {
	nets := h.cfg.SerialBridge.AuthorizedNets
	if len(nets) == 0 {
		nets = h.cfg.AuthorizedNets
	}
	if len(nets) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, c := range nets {
		_, cidr, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// Status handles GET /api/serial-bridge/status — small JSON envelope
// so the panel can decide whether to even render the bridge UI.
func (h *SerialBridgeHandler) Status(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":     h.cfg.SerialBridge.Enabled,
		"basePort":    h.cfg.SerialBridge.BasePort,
		"maxSessions": h.cfg.SerialBridge.MaxSessions,
		"openBusIds":  h.mgr.OpenBusIDs(),
	})
}

// Sessions handles GET /api/serial-bridge/sessions — full per-session
// state (port, framing, connected client). The panel polls this to
// paint a "Bridge active 115200 8N1" chip.
func (h *SerialBridgeHandler) Sessions(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sessions": h.mgr.Sessions(),
	})
}

// SessionForBusID handles GET /api/serial-bridge/sessions/{busId}.
// Drill-down endpoint: returns 404 when no live session exists for
// the bus id so the panel can distinguish "never opened" from
// "open but currently disconnected".
func (h *SerialBridgeHandler) SessionForBusID(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	busID := chi.URLParam(r, "busId")
	sess := h.mgr.SessionFor(busID)
	if sess == nil {
		writeError(w, http.StatusNotFound, "no bridge session for bus id")
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

// Open handles POST /api/serial-bridge/open. Body: `{"busId": "1-1.3"}`.
//
// Fails with 503 when the bridge is disabled in config (operator
// deliberately opted out — the panel should hide the button rather
// than let it 503), 404 when the bus id has no /dev/ttyACMx mapping
// (device unplugged or non-CDC), 409 when all session slots are taken,
// and 423 ("Locked") when the device is held by another userland
// process (ModemManager grabbed it during enumeration, brltty stole
// a CH340, etc.).
func (h *SerialBridgeHandler) Open(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	if !h.cfg.SerialBridge.Enabled {
		writeError(w, http.StatusServiceUnavailable, "serial bridge disabled in config")
		return
	}
	var req busRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BusID == "" {
		writeError(w, http.StatusBadRequest, "busId required")
		return
	}
	// Defensive guard: don't take the bridge slot if the device isn't
	// actually a CDC-class device. The panel SHOULD be enforcing this
	// already (the auto-mode selector lives there), but a misbehaving
	// client shouldn't be able to wedge a bridge listener on a
	// random pendrive.
	dev, err := usblister.FindByBusID(req.BusID)
	if err == nil && !dev.IsCDC() {
		writeError(w, http.StatusUnprocessableEntity,
			"device is not CDC-class; use USB/IP transport instead")
		return
	}
	sess, err := h.mgr.Open(req.BusID)
	if err != nil {
		status := mapBridgeError(err)
		log.Warn().Err(err).Str("busId", req.BusID).Int("status", status).Msg("serial bridge open rejected")
		writeError(w, status, err.Error())
		return
	}
	log.Info().
		Str("busId", req.BusID).
		Int("tcpPort", sess.TCPPort).
		Str("devicePath", sess.DevicePath).
		Msg("serial bridge opened")
	writeJSON(w, http.StatusOK, sess)
}

// Reset handles POST /api/serial-bridge/reset. Body:
//   {"busId": "1-1.3", "pulseMs": 50}
//
// Pulses DTR low on the live bridge session for `busId` then re-asserts
// it, mimicking the open-then-close-then-open dance Arduino's reset
// circuit expects. Useful for clients that don't synthesize DTR via
// RFC 2217 (raw TCP scopes, com0com pairs that mishandle modem-control
// across the pair). `pulseMs` is optional and clamped to [10, 5000];
// the default (50 ms) is the optiboot reference width.
//
// Failure modes:
//   - 503: bridge disabled in config (no listener, nothing to pulse)
//   - 400: missing / invalid busId
//   - 404: no live session for busId — caller must Open() first
//   - 500: kernel-side ioctl failed (device unplugged mid-pulse, etc.)
func (h *SerialBridgeHandler) Reset(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	if !h.cfg.SerialBridge.Enabled {
		writeError(w, http.StatusServiceUnavailable, "serial bridge disabled in config")
		return
	}
	var req struct {
		BusID   string `json:"busId"`
		PulseMs int    `json:"pulseMs,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BusID == "" {
		writeError(w, http.StatusBadRequest, "busId required")
		return
	}
	if err := h.mgr.Reset(req.BusID, req.PulseMs); err != nil {
		status := mapBridgeError(err)
		log.Warn().Err(err).Str("busId", req.BusID).Int("status", status).Msg("serial bridge reset rejected")
		writeError(w, status, err.Error())
		return
	}
	log.Info().Str("busId", req.BusID).Int("pulseMs", req.PulseMs).Msg("serial bridge reset (DTR pulse) ok")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Close handles DELETE /api/serial-bridge/open. Body: `{"busId": "1-1.3"}`.
// Idempotent — closing a non-existent session is not an error.
func (h *SerialBridgeHandler) Close(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	var req busRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BusID == "" {
		writeError(w, http.StatusBadRequest, "busId required")
		return
	}
	if err := h.mgr.Close(req.BusID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Info().Str("busId", req.BusID).Msg("serial bridge closed")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// mapBridgeError translates the package's sentinel errors into HTTP
// status codes the panel can act on.
func mapBridgeError(err error) int {
	switch {
	case errors.Is(err, serbridge.ErrDisabled):
		return http.StatusServiceUnavailable
	case errors.Is(err, serbridge.ErrAlreadyOpen):
		return http.StatusOK // idempotent — Open returns existing session
	case errors.Is(err, serbridge.ErrNoFreeSlots):
		return http.StatusConflict
	case errors.Is(err, serbridge.ErrDeviceNotFound):
		return http.StatusNotFound
	case errors.Is(err, serbridge.ErrDeviceBusy):
		return http.StatusLocked // 423 — semantic match for "ModemManager has it"
	case errors.Is(err, serbridge.ErrSessionNotFound):
		return http.StatusNotFound
	}
	// Unknown error — defensive 500 + the message gets logged so the
	// operator can dig into it via journalctl.
	if strings.Contains(strings.ToLower(err.Error()), "busy") {
		return http.StatusLocked
	}
	return http.StatusInternalServerError
}
