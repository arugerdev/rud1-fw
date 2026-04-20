package handlers

import (
	"net/http"

	"github.com/rs/zerolog/log"

	usblister "github.com/rud1-es/rud1-fw/internal/infrastructure/usb"
)

// USBHandler serves USB-related API endpoints.
type USBHandler struct{}

// NewUSBHandler creates a USBHandler.
func NewUSBHandler() *USBHandler {
	return &USBHandler{}
}

// List handles GET /api/usb/devices.
func (h *USBHandler) List(w http.ResponseWriter, r *http.Request) {
	devices, err := usblister.List()
	if err != nil {
		log.Error().Err(err).Msg("usb list failed")
		writeError(w, http.StatusInternalServerError, "failed to list USB devices")
		return
	}
	writeJSON(w, http.StatusOK, devices)
}
