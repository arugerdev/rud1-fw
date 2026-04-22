package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/bootidentity"
)

// IdentityHandler exposes the device's (code, pin, QR) identity over the
// local HTTP API so rud1-app can render the claim card + QR code without
// reading the /boot file directly.
//
// The local API is bound to localhost (or the AP network during setup), so
// exposing the PIN here is comparable to printing it on the sticker: it
// requires either physical access to the device or access to its LAN.
type IdentityHandler struct {
	identity bootidentity.Identity
}

// NewIdentityHandler returns a handler that always serves the given identity.
// Identity is immutable for the lifetime of the SD card so no mutex is needed.
func NewIdentityHandler(id bootidentity.Identity) *IdentityHandler {
	return &IdentityHandler{identity: id}
}

type identityResponse struct {
	RegistrationCode string `json:"registrationCode"`
	RegistrationPin  string `json:"registrationPin"`
	QRDeeplink       string `json:"qrDeeplink"`
}

// Get returns the identity as JSON. GET /api/identity.
func (h *IdentityHandler) Get(w http.ResponseWriter, _ *http.Request) {
	resp := identityResponse{
		RegistrationCode: h.identity.RegistrationCode,
		RegistrationPin:  h.identity.RegistrationPin,
		QRDeeplink:       h.identity.QRDeeplink(),
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}
