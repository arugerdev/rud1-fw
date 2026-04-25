package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/server/middleware"
)

// freshCfg returns a Default config persisted to a temp directory so
// Save() succeeds. Each subtest gets its own copy — there is no shared
// mutable state between tests.
func freshCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default()
	dir := t.TempDir()
	cfg.Path = filepath.Join(dir, "config.yaml")
	// Required for Validate() inside Save().
	cfg.Server.Port = 7070
	return cfg
}

func newRouter(cfg *config.Config, h *SetupHandler, token string) *chi.Mux {
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(SetupGate(cfg, token))
		r.Get("/api/setup/state", h.State)
		r.Get("/api/setup/health", h.Health)
		r.Post("/api/setup/general", h.General)
		r.Post("/api/setup/complete", h.Complete)
	})
	r.Group(func(r chi.Router) {
		r.Use(middleware.BearerAuth(token))
		r.Post("/api/setup/reset", h.Reset)
	})
	return r
}

// TestSetupHandler_StateNoAuth: GET /api/setup/state without bearer
// token while Setup.Complete=false must return 200.
func TestSetupHandler_StateNoAuth(t *testing.T) {
	cfg := freshCfg(t)
	h := NewSetupHandler(cfg, SetupHandlerDeps{
		SerialNumber:    func() string { return "RUD1-TEST" },
		FirmwareVersion: func() string { return "0.0.0-test" },
		WiFiInterface:   "wlan0",
		APInterface:     "wlan0",
	})
	r := newRouter(cfg, h, "secret-token")

	req := httptest.NewRequest(http.MethodGet, "/api/setup/state", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	var got setupStateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Complete {
		t.Fatalf("complete = true, want false on fresh config")
	}
	if got.DeviceSerial != "RUD1-TEST" {
		t.Fatalf("deviceSerial = %q, want RUD1-TEST", got.DeviceSerial)
	}
	if got.Interfaces.WiFi != "wlan0" || got.Interfaces.AP != "wlan0" {
		t.Fatalf("interfaces = %+v, want wlan0/wlan0", got.Interfaces)
	}
}

// TestSetupHandler_GeneralPersistsAndValidates: happy path persists fields
// to config; oversized inputs are rejected with 400.
func TestSetupHandler_GeneralPersistsAndValidates(t *testing.T) {
	cfg := freshCfg(t)
	h := NewSetupHandler(cfg, SetupHandlerDeps{
		SerialNumber: func() string { return "RUD1-A" },
	})
	r := newRouter(cfg, h, "")

	// Happy path.
	body := strings.NewReader(`{"deviceName":"Taller-A","deviceLocation":"Madrid","notes":"prod"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/setup/general", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("happy: status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	if cfg.Setup.DeviceName != "Taller-A" {
		t.Fatalf("config.Setup.DeviceName = %q, want Taller-A", cfg.Setup.DeviceName)
	}
	if cfg.Setup.DeviceLocation != "Madrid" {
		t.Fatalf("config.Setup.DeviceLocation = %q, want Madrid", cfg.Setup.DeviceLocation)
	}

	// Empty name → 400.
	emptyReq := httptest.NewRequest(http.MethodPost, "/api/setup/general",
		strings.NewReader(`{"deviceName":""}`))
	emptyReq.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	r.ServeHTTP(rr2, emptyReq)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("empty name: status = %d, want 400", rr2.Code)
	}

	// 65-char name → 400.
	longName := strings.Repeat("x", 65)
	longReq := httptest.NewRequest(http.MethodPost, "/api/setup/general",
		strings.NewReader(`{"deviceName":"`+longName+`"}`))
	longReq.Header.Set("Content-Type", "application/json")
	rr3 := httptest.NewRecorder()
	r.ServeHTTP(rr3, longReq)
	if rr3.Code != http.StatusBadRequest {
		t.Fatalf("65-char name: status = %d, want 400", rr3.Code)
	}
}

// TestSetupHandler_CompleteFlipsAndLocksDownEndpoints: POST /complete
// flips Setup.Complete=true; subsequent unauthenticated GET /state must
// be rejected by the gate (the same BearerAuth middleware would reply
// 401 missing/malformed header).
func TestSetupHandler_CompleteFlipsAndLocksDownEndpoints(t *testing.T) {
	cfg := freshCfg(t)
	h := NewSetupHandler(cfg, SetupHandlerDeps{})
	const token = "secret-token"
	r := newRouter(cfg, h, token)

	// Pre-seed deviceName so /complete passes its guard.
	gen := httptest.NewRequest(http.MethodPost, "/api/setup/general",
		strings.NewReader(`{"deviceName":"Taller-A"}`))
	gen.Header.Set("Content-Type", "application/json")
	gr := httptest.NewRecorder()
	r.ServeHTTP(gr, gen)
	if gr.Code != http.StatusOK {
		t.Fatalf("seed general: status = %d body=%s", gr.Code, gr.Body.String())
	}

	// /complete (no auth, allowed because Complete=false).
	cp := httptest.NewRequest(http.MethodPost, "/api/setup/complete", nil)
	cr := httptest.NewRecorder()
	r.ServeHTTP(cr, cp)
	if cr.Code != http.StatusOK {
		t.Fatalf("complete: status = %d body=%s", cr.Code, cr.Body.String())
	}
	if !cfg.Setup.Complete {
		t.Fatalf("Setup.Complete still false after POST /complete")
	}
	if cfg.Setup.CompletedAt == 0 {
		t.Fatalf("Setup.CompletedAt not stamped")
	}

	// Now GET /state without bearer — gate must enforce auth.
	req := httptest.NewRequest(http.MethodGet, "/api/setup/state", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("post-complete state w/o auth: status = %d, want 401 (body=%s)", rr.Code, rr.Body.String())
	}

	// With bearer — should succeed again.
	authReq := httptest.NewRequest(http.MethodGet, "/api/setup/state", nil)
	authReq.Header.Set("Authorization", "Bearer "+token)
	ar := httptest.NewRecorder()
	r.ServeHTTP(ar, authReq)
	if ar.Code != http.StatusOK {
		t.Fatalf("post-complete state with auth: status = %d (body=%s)", ar.Code, ar.Body.String())
	}
}

// TestSetupHandler_HealthAggregates wires three stub checkers (2 ok, 1 fail)
// and asserts the summary reflects the reality.
func TestSetupHandler_HealthAggregates(t *testing.T) {
	cfg := freshCfg(t)
	checkers := []SetupHealthChecker{
		func(_ context.Context) SetupHealthCheck {
			return SetupHealthCheck{ID: "internet", Label: "Conexión a internet", Ok: true, Detail: "ok"}
		},
		func(_ context.Context) SetupHealthCheck {
			return SetupHealthCheck{ID: "vpn", Label: "Túnel WireGuard", Ok: true, Detail: "ok"}
		},
		func(_ context.Context) SetupHealthCheck {
			return SetupHealthCheck{ID: "cloud", Label: "Conexión a rud1.es", Ok: false, Detail: "Pendiente"}
		},
	}
	h := NewSetupHandler(cfg, SetupHandlerDeps{HealthCheckers: checkers})
	r := newRouter(cfg, h, "")

	req := httptest.NewRequest(http.MethodGet, "/api/setup/health", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	var got setupHealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Summary.Total != 3 || got.Summary.Ok != 2 || got.Summary.Failed != 1 {
		t.Fatalf("summary = %+v, want total=3 ok=2 failed=1", got.Summary)
	}
	if len(got.Checks) != 3 {
		t.Fatalf("len(checks) = %d, want 3", len(got.Checks))
	}
	// Order preserved.
	if got.Checks[0].ID != "internet" || got.Checks[2].ID != "cloud" {
		t.Fatalf("checks order = [%s,%s,%s], want [internet,vpn,cloud]",
			got.Checks[0].ID, got.Checks[1].ID, got.Checks[2].ID)
	}
}

// TestSetupHandler_ResetRequiresAuth ensures /reset is locked behind
// BearerAuth even when Setup.Complete is still false (it's destructive
// and shouldn't be reachable to a casual AP-side wizard).
func TestSetupHandler_ResetRequiresAuth(t *testing.T) {
	cfg := freshCfg(t)
	h := NewSetupHandler(cfg, SetupHandlerDeps{})
	const token = "secret-token"
	r := newRouter(cfg, h, token)

	req := httptest.NewRequest(http.MethodPost, "/api/setup/reset", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}

	// With token clears state.
	cfg.Setup.DeviceName = "leftover"
	cfg.Setup.Complete = true
	authReq := httptest.NewRequest(http.MethodPost, "/api/setup/reset", nil)
	authReq.Header.Set("Authorization", "Bearer "+token)
	ar := httptest.NewRecorder()
	r.ServeHTTP(ar, authReq)
	if ar.Code != http.StatusOK {
		t.Fatalf("auth reset: status = %d (body=%s)", ar.Code, ar.Body.String())
	}
	if cfg.Setup.Complete || cfg.Setup.DeviceName != "" {
		t.Fatalf("after reset: complete=%v deviceName=%q (want false / \"\")", cfg.Setup.Complete, cfg.Setup.DeviceName)
	}
}
