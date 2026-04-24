package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/rud1-es/rud1-fw/internal/config"
)

// TestSessionForBusID_UnauthorizedReturns403 checks that an inbound request
// from an IP that is outside the configured authorized_nets CIDR is rejected
// with 403 before the handler ever touches usblister.SessionFor. Mirrors the
// same guard present on /api/usbip/sessions.
func TestSessionForBusID_UnauthorizedReturns403(t *testing.T) {
	h := &USBIPHandler{
		full: &config.Config{},
		cfg: &config.USBConfig{
			// 10.0.0.0/8 is narrow enough that a request from 127.0.0.1 falls
			// outside it — triggers the authorization rejection path.
			AuthorizedNets: []string{"10.0.0.0/8"},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/usbip/sessions/1-1", nil)
	req.RemoteAddr = "127.0.0.1:55555"
	// Attach chi URL params so the handler can extract busId if it gets that
	// far (it shouldn't — auth should short-circuit).
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("busId", "1-1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	h.SessionForBusID(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — body=%s", rr.Code, rr.Body.String())
	}
}

// TestSessionForBusID_EmptyBusIdReturns400 exercises the guard that rejects
// a request with a missing path param. The authorized_nets list is left empty
// so the request passes the IP check and reaches the busId validation.
func TestSessionForBusID_EmptyBusIdReturns400(t *testing.T) {
	h := &USBIPHandler{
		full: &config.Config{},
		cfg:  &config.USBConfig{}, // no authorized_nets => open access
	}

	req := httptest.NewRequest(http.MethodGet, "/api/usbip/sessions/", nil)
	// Explicitly attach an empty busId via chi's route context so the handler
	// sees "" (which is what chi.URLParam returns when the param is missing).
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("busId", "")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rr := httptest.NewRecorder()
	h.SessionForBusID(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body["error"] != "busId required" {
		t.Fatalf("error = %q, want %q", body["error"], "busId required")
	}
}
