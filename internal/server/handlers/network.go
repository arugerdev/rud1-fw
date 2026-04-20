package handlers

import (
	"net/http"

	"github.com/rs/zerolog/log"

	domainnet "github.com/rud1-es/rud1-fw/internal/domain/network"
)

// NetworkHandler serves network-related API endpoints.
type NetworkHandler struct {
	scanner func() (*domainnet.Status, error)
}

// NewNetworkHandler creates a NetworkHandler backed by the provided scanner function.
func NewNetworkHandler(scanner func() (*domainnet.Status, error)) *NetworkHandler {
	return &NetworkHandler{scanner: scanner}
}

// Status handles GET /api/network/status.
func (h *NetworkHandler) Status(w http.ResponseWriter, r *http.Request) {
	st, err := h.scanner()
	if err != nil {
		log.Error().Err(err).Msg("network scan failed")
		writeError(w, http.StatusInternalServerError, "failed to scan network interfaces")
		return
	}
	writeJSON(w, http.StatusOK, st)
}
