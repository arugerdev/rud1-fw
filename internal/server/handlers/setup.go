// Package handlers — first-boot setup wizard endpoints.
//
// The setup wizard is the very first thing rud1-app shows on a freshly
// imaged Pi: the installer associates with the device's setup AP, opens
// the panel, and walks through identification, services check, and
// completion. Until the wizard is complete the agent runs with a
// permissive auth posture so the chicken-and-egg problem (no token
// agreed yet) doesn't block the flow.
//
// Endpoints (contract shared with rud1-app):
//
//	GET  /api/setup/state    — what the wizard knows so far + device facts
//	POST /api/setup/general  — persist deviceName/location/notes
//	POST /api/setup/complete — flip Complete=true, drop AP if uplink up
//	GET  /api/setup/health   — user-facing services check
//	POST /api/setup/reset    — clear the wizard state (auth ALWAYS required)
//
// Auth gating is handled by SetupGate (in this file): while
// `cfg.Setup.Complete == false`, the first four endpoints are open;
// after completion, they require BearerAuth. /reset always requires auth
// because it's destructive and bound to /api/setup/* on a paired device.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/audit/configlog"
	"github.com/rud1-es/rud1-fw/internal/server/middleware"
)

// SetupHealthChecker is a single user-facing service check. The handler
// invokes one per check in the order it wants to render them. Each check
// MUST return without panicking even when the underlying service is nil
// or unreachable — degraded checks should report `Ok=false, Detail="..."`
// rather than erroring out.
type SetupHealthChecker func(ctx context.Context) SetupHealthCheck

// SetupHealthCheck is the wire shape returned by GET /api/setup/health.
type SetupHealthCheck struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Ok     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// SetupHandlerDeps bundles the read-only dependencies the handler needs
// to render /api/setup/state and /api/setup/health. Each closure is
// invoked at handler-time so the data is always fresh — the caller should
// NOT memoise.
type SetupHandlerDeps struct {
	// SerialNumber returns the device's stable serial (mirrors the value
	// surfaced by /api/identity). Required.
	SerialNumber func() string
	// FirmwareVersion returns the build version string. May return "" on
	// dev builds.
	FirmwareVersion func() string
	// WiFiInterface / APInterface are the NIC names from config; surfaced
	// for diagnostic clarity in the wizard UI.
	WiFiInterface string
	APInterface   string
	// HealthCheckers, when non-empty, replaces the default health probes.
	// Tests inject stubs here. Production wiring builds the slice from
	// the live wireguard / cloud / usbip handles.
	HealthCheckers []SetupHealthChecker
}

// SetupHandler exposes the wizard endpoints. It guards mutations behind
// a single sync.Mutex so concurrent POSTs from a flaky phone don't
// interleave config writes — Save() is itself atomic but we want the
// in-memory state to match what we just persisted.
type SetupHandler struct {
	cfg      *config.Config
	deps     SetupHandlerDeps
	mu       sync.Mutex
	auditLog auditLogger // never nil after construction (LoggerNoop default)
}

// NewSetupHandler wires a SetupHandler around the live config + deps.
func NewSetupHandler(cfg *config.Config, deps SetupHandlerDeps) *SetupHandler {
	if deps.SerialNumber == nil {
		deps.SerialNumber = func() string { return "" }
	}
	if deps.FirmwareVersion == nil {
		deps.FirmwareVersion = func() string { return "" }
	}
	return &SetupHandler{cfg: cfg, deps: deps, auditLog: configlog.LoggerNoop{}}
}

// SetAuditLogger swaps in a real audit logger after construction. Wired
// from agent.go where the configlog.DiskLogger is built. Calling with
// nil reverts to the no-op logger.
func (h *SetupHandler) SetAuditLogger(l auditLogger) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if l == nil {
		h.auditLog = configlog.LoggerNoop{}
		return
	}
	h.auditLog = l
}

// setupAuditSnapshot returns a JSON-serialisable copy of cfg.Setup with
// the free-form Notes field passed through Redact() in case it ever
// contains a key we want to keep out of the audit trail. Notes is
// operator-supplied free text; the rest of the block is short metadata.
func setupAuditSnapshot(s config.SetupConfig) map[string]any {
	notesField := configlog.Redact(map[string]any{"notes": s.Notes})
	return map[string]any{
		"complete":       s.Complete,
		"deviceName":     s.DeviceName,
		"deviceLocation": s.DeviceLocation,
		"notes":          notesField["notes"],
		"completedAt":    s.CompletedAt,
	}
}

// auditSetup is the shared back-end for the three setup mutations. It
// never returns an error: a failed audit write is warn-logged and
// dropped so the originating request always wins.
func (h *SetupHandler) auditSetup(ctx context.Context, action string, prev, next config.SetupConfig, ok bool, errMsg string) {
	if h.auditLog == nil {
		return
	}
	var nextSnap any
	if ok {
		nextSnap = setupAuditSnapshot(next)
	}
	if err := h.auditLog.Append(ctx, configlog.Entry{
		Action:   action,
		Actor:    "operator",
		Previous: setupAuditSnapshot(prev),
		Next:     nextSnap,
		OK:       ok,
		Error:    errMsg,
	}); err != nil {
		log.Warn().Err(err).Str("action", action).Msg("audit append failed (non-fatal)")
	}
}

// ── State ───────────────────────────────────────────────────────────────────

type setupStateResponse struct {
	Complete        bool                       `json:"complete"`
	DeviceName      string                     `json:"deviceName"`
	DeviceLocation  string                     `json:"deviceLocation"`
	Notes           string                     `json:"notes"`
	CompletedAt     *int64                     `json:"completedAt"`
	DeviceSerial    string                     `json:"deviceSerial"`
	FirmwareVersion string                     `json:"firmwareVersion"`
	Interfaces      setupStateResponseIfaces   `json:"interfaces"`
}

type setupStateResponseIfaces struct {
	WiFi string `json:"wifi"`
	AP   string `json:"ap"`
}

// State — GET /api/setup/state. No auth required when Setup.Complete=false
// (the gate middleware enforces that); always low-PII so even an open
// response on a setup AP doesn't leak anything not on the sticker.
func (h *SetupHandler) State(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.snapshot())
}

func (h *SetupHandler) snapshot() setupStateResponse {
	h.mu.Lock()
	defer h.mu.Unlock()
	var completedAt *int64
	if h.cfg.Setup.CompletedAt > 0 {
		v := h.cfg.Setup.CompletedAt
		completedAt = &v
	}
	return setupStateResponse{
		Complete:        h.cfg.Setup.Complete,
		DeviceName:      h.cfg.Setup.DeviceName,
		DeviceLocation:  h.cfg.Setup.DeviceLocation,
		Notes:           h.cfg.Setup.Notes,
		CompletedAt:     completedAt,
		DeviceSerial:    h.deps.SerialNumber(),
		FirmwareVersion: h.deps.FirmwareVersion(),
		Interfaces: setupStateResponseIfaces{
			WiFi: h.deps.WiFiInterface,
			AP:   h.deps.APInterface,
		},
	}
}

// ── General ─────────────────────────────────────────────────────────────────

type setupGeneralRequest struct {
	DeviceName     string `json:"deviceName"`
	DeviceLocation string `json:"deviceLocation"`
	Notes          string `json:"notes"`
}

// General — POST /api/setup/general. Persists the operator-friendly
// identification fields. Length-validates each one (1..64 / 0..128 / 0..512).
func (h *SetupHandler) General(w http.ResponseWriter, r *http.Request) {
	var req setupGeneralRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(req.DeviceName)
	location := strings.TrimSpace(req.DeviceLocation)
	notes := strings.TrimSpace(req.Notes)

	if n := len([]rune(name)); n < 1 || n > 64 {
		writeError(w, http.StatusBadRequest, "deviceName length must be between 1 and 64 characters")
		return
	}
	if n := len([]rune(location)); n > 128 {
		writeError(w, http.StatusBadRequest, "deviceLocation length must be at most 128 characters")
		return
	}
	if n := len([]rune(notes)); n > 512 {
		writeError(w, http.StatusBadRequest, "notes length must be at most 512 characters")
		return
	}

	h.mu.Lock()
	prev := h.cfg.Setup
	h.cfg.Setup.DeviceName = name
	h.cfg.Setup.DeviceLocation = location
	h.cfg.Setup.Notes = notes
	saveErr := h.cfg.Save()
	if saveErr != nil {
		// Roll back the in-memory mutation so the audit `previous`
		// (and any subsequent reader) reflects the on-disk truth.
		h.cfg.Setup = prev
	}
	next := h.cfg.Setup
	h.mu.Unlock()
	if saveErr != nil {
		log.Warn().Err(saveErr).Msg("setup: save general failed")
		h.auditSetup(r.Context(), "setup.general.set", prev, prev, false, "save: "+saveErr.Error())
		writeError(w, http.StatusInternalServerError, "failed to persist setup")
		return
	}

	h.auditSetup(r.Context(), "setup.general.set", prev, next, true, "")
	writeJSON(w, http.StatusOK, h.snapshot())
}

// ── Complete ────────────────────────────────────────────────────────────────

// Complete — POST /api/setup/complete. Flips Complete=true and stamps
// CompletedAt. After this call the supervisor's IsSetupComplete getter
// flips on the next tick and the AP is dropped (assuming uplink is up).
// Empty body — no fields to validate beyond what /general already saved.
func (h *SetupHandler) Complete(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	prev := h.cfg.Setup
	if strings.TrimSpace(h.cfg.Setup.DeviceName) == "" {
		h.mu.Unlock()
		h.auditSetup(r.Context(), "setup.complete", prev, prev, false, "deviceName must be set before completing setup")
		writeError(w, http.StatusBadRequest, "deviceName must be set before completing setup (POST /api/setup/general first)")
		return
	}
	h.cfg.Setup.Complete = true
	h.cfg.Setup.CompletedAt = time.Now().Unix()
	saveErr := h.cfg.Save()
	if saveErr != nil {
		h.cfg.Setup = prev
	}
	next := h.cfg.Setup
	h.mu.Unlock()
	if saveErr != nil {
		log.Warn().Err(saveErr).Msg("setup: save complete failed")
		h.auditSetup(r.Context(), "setup.complete", prev, prev, false, "save: "+saveErr.Error())
		writeError(w, http.StatusInternalServerError, "failed to persist setup completion")
		return
	}
	log.Info().
		Str("device_name", h.cfg.Setup.DeviceName).
		Str("device_location", h.cfg.Setup.DeviceLocation).
		Msg("setup wizard completed")
	h.auditSetup(r.Context(), "setup.complete", prev, next, true, "")
	writeJSON(w, http.StatusOK, h.snapshot())
}

// ── Reset ───────────────────────────────────────────────────────────────────

// Reset — POST /api/setup/reset. Always requires BearerAuth (wired in
// server.go outside the SetupGate group). Clears the general fields and
// flips Complete=false so the wizard re-runs on the next reload.
func (h *SetupHandler) Reset(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	prev := h.cfg.Setup
	h.cfg.Setup.Complete = false
	h.cfg.Setup.DeviceName = ""
	h.cfg.Setup.DeviceLocation = ""
	h.cfg.Setup.Notes = ""
	h.cfg.Setup.CompletedAt = 0
	saveErr := h.cfg.Save()
	if saveErr != nil {
		h.cfg.Setup = prev
	}
	next := h.cfg.Setup
	h.mu.Unlock()
	if saveErr != nil {
		log.Warn().Err(saveErr).Msg("setup: save reset failed")
		h.auditSetup(r.Context(), "setup.reset", prev, prev, false, "save: "+saveErr.Error())
		writeError(w, http.StatusInternalServerError, "failed to persist setup reset")
		return
	}
	log.Warn().Msg("setup wizard state reset (will re-run on next AP raise)")
	h.auditSetup(r.Context(), "setup.reset", prev, next, true, "")
	writeJSON(w, http.StatusOK, h.snapshot())
}

// ── Health ──────────────────────────────────────────────────────────────────

type setupHealthSummary struct {
	Total  int `json:"total"`
	Ok     int `json:"ok"`
	Failed int `json:"failed"`
}

type setupHealthResponse struct {
	Checks  []SetupHealthCheck `json:"checks"`
	Summary setupHealthSummary `json:"summary"`
}

// Health — GET /api/setup/health. Runs each registered checker (with a
// short per-check budget) and aggregates the result. Order is preserved.
func (h *SetupHandler) Health(w http.ResponseWriter, r *http.Request) {
	checkers := h.deps.HealthCheckers
	if len(checkers) == 0 {
		// Empty deps still produce a 200 with an empty list — clearer
		// than a 500 when the wiring is incomplete in dev.
		writeJSON(w, http.StatusOK, setupHealthResponse{Checks: []SetupHealthCheck{}})
		return
	}
	out := make([]SetupHealthCheck, 0, len(checkers))
	summary := setupHealthSummary{}
	for _, fn := range checkers {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		c := fn(ctx)
		cancel()
		out = append(out, c)
		summary.Total++
		if c.Ok {
			summary.Ok++
		} else {
			summary.Failed++
		}
	}
	writeJSON(w, http.StatusOK, setupHealthResponse{Checks: out, Summary: summary})
}

// ── Auth gate ───────────────────────────────────────────────────────────────

// SetupGate wraps a handler with the wizard's chicken-and-egg auth rule:
//
//   - while cfg.Setup.Complete == false → no auth (open on the setup AP)
//   - once flipped to true             → behave like middleware.BearerAuth
//
// Wire this OUTSIDE the global BearerAuth group in server.go: state /
// general / complete / health all use this gate; only /reset uses the
// regular BearerAuth (always-on) since it's destructive.
//
// expectedToken == "" reverts to "no auth required" everywhere — same
// semantics as middleware.BearerAuth.
func SetupGate(cfg *config.Config, expectedToken string) func(http.Handler) http.Handler {
	bearer := middleware.BearerAuth(expectedToken)
	return func(next http.Handler) http.Handler {
		bearerWrapped := bearer(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Read at request-time so a POST /api/setup/complete that
			// just saved the new state immediately tightens the gate
			// for any in-flight follow-up requests.
			if cfg.Setup.Complete {
				bearerWrapped.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
