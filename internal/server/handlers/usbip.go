package handlers

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
	usblister "github.com/rud1-es/rud1-fw/internal/infrastructure/usb"
)

// USBIPHandler manages USB/IP export operations.
type USBIPHandler struct {
	server  *usblister.USBIPServer
	cfg     *config.USBConfig
}

// NewUSBIPHandler creates and (if enabled) starts the USB/IP server.
func NewUSBIPHandler(cfg *config.USBConfig) *USBIPHandler {
	srv := usblister.NewUSBIPServer(cfg.BindPort)
	if cfg.USBIPEnabled {
		if err := srv.Start(); err != nil {
			log.Warn().Err(err).Msg("usbipd start failed — USB/IP exports unavailable")
		} else {
			log.Info().Int("port", cfg.BindPort).Msg("usbipd started")
		}
	}
	return &USBIPHandler{server: srv, cfg: cfg}
}

// Stop shuts down the USB/IP daemon.
func (h *USBIPHandler) Stop() { h.server.Stop() }

// isAuthorized checks whether the request comes from an authorized CIDR.
func (h *USBIPHandler) isAuthorized(r *http.Request) bool {
	if len(h.cfg.AuthorizedNets) == 0 {
		return true // no restrictions configured
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range h.cfg.AuthorizedNets {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Status handles GET /api/usbip/status.
func (h *USBIPHandler) Status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":   h.cfg.USBIPEnabled,
		"port":      h.cfg.BindPort,
		"exported":  h.server.ExportedDevices(),
	})
}

// Exportable handles GET /api/usbip/exportable.
func (h *USBIPHandler) Exportable(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	ids, err := usblister.ListExportable()
	if err != nil {
		log.Error().Err(err).Msg("list exportable failed")
		writeError(w, http.StatusInternalServerError, "failed to list exportable devices")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"devices": ids})
}

type exportRequest struct {
	BusID string `json:"busId"`
}

// Export handles POST /api/usbip/export — binds a USB device for remote access.
func (h *USBIPHandler) Export(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	var req exportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BusID == "" {
		writeError(w, http.StatusBadRequest, "busId required")
		return
	}
	if err := h.server.Export(req.BusID); err != nil {
		log.Error().Err(err).Str("busId", req.BusID).Msg("usbip export failed")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Unexport handles DELETE /api/usbip/export — unbinds a USB device.
func (h *USBIPHandler) Unexport(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusForbidden, "client IP not in authorized_nets")
		return
	}
	var req exportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BusID == "" {
		writeError(w, http.StatusBadRequest, "busId required")
		return
	}
	if err := h.server.Unexport(req.BusID); err != nil {
		log.Error().Err(err).Str("busId", req.BusID).Msg("usbip unexport failed")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
