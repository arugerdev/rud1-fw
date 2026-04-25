// Package handlers — runtime NTP probe configuration endpoint.
//
// Endpoints:
//
//	GET /api/system/ntp-probe-config — current probe state (enabled,
//	    servers, per-server timeout)
//	PUT /api/system/ntp-probe-config — update + persist to config.yaml
//
// The probe itself is implemented in system_time_health.go and gates the
// `clockSkewSeconds` field in the time-health response. Until iter 29 the
// only way to flip it on/off was to edit /etc/rud1-agent/config.yaml by
// hand and restart the agent — operators rarely have shell access on the
// Pi, so we surface the toggle to the local panel + cloud Settings page
// via this dedicated, bounded endpoint.
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
)

// MaxNTPProbeServers caps the number of servers the operator can wire up
// at once. Each entry triggers an outbound UDP query during a probe; we
// don't want a typo in the UI to flood pool.ntp.org with traffic from a
// hot-loop misconfiguration. 8 is generous (the real-world list rarely
// exceeds 4) and matches the public-pool fair-use rotation typical for
// ntp.conf files.
const MaxNTPProbeServers = 8

// NTPProbeMinTimeoutSeconds and NTPProbeMaxTimeoutSeconds bound the
// per-server budget. Below 1s the SNTP roundtrip rarely completes; above
// 30s a hung probe would dominate the heartbeat tick and starve other
// telemetry. The default lives in config.go (2s).
const (
	NTPProbeMinTimeoutSeconds = 1
	NTPProbeMaxTimeoutSeconds = 30
)

// SystemNTPProbeConfigHandler serves the runtime NTP probe config
// endpoints. It mutates the live cfg.System fields under its own mutex
// and pushes the new options into the time-health handler so the next
// /api/system/time-health call (and the next heartbeat tick) sees them.
//
// The handler holds a pointer to the SystemTimeHealthHandler so SetProbeOptions
// can be called atomically right after the disk Save. Without that
// coupling, a PUT followed quickly by a GET on /time-health would still
// see the pre-PUT config until the handler restarted.
type SystemNTPProbeConfigHandler struct {
	mu      sync.Mutex
	cfg     *config.Config
	timeH   *SystemTimeHealthHandler
	onApply func(opts ExternalNTPProbeOptions) // optional hook (heartbeat throttle reset)
}

// NewSystemNTPProbeConfigHandler wires the handler with the live config
// pointer (so PUT can persist) and the time-health handler (so PUT can
// push live options for immediate effect on the next request). Both
// pointers MUST be non-nil — there's no useful zero-value fallback.
func NewSystemNTPProbeConfigHandler(cfg *config.Config, timeH *SystemTimeHealthHandler) *SystemNTPProbeConfigHandler {
	return &SystemNTPProbeConfigHandler{cfg: cfg, timeH: timeH}
}

// SetOnApply registers an optional callback invoked after a successful
// PUT. The agent uses this to reset its time-health throttle so the
// next heartbeat re-sends the (now updated) timeHealth block instead
// of waiting for the 1-hour keepalive.
func (h *SystemNTPProbeConfigHandler) SetOnApply(fn func(opts ExternalNTPProbeOptions)) {
	h.mu.Lock()
	h.onApply = fn
	h.mu.Unlock()
}

// ntpProbeConfigResponse is the shape on the wire for both GET and PUT
// responses. timeoutSeconds is exposed as an int rather than a Go
// time.Duration so JSON consumers don't have to parse "2s" strings —
// we keep the wire surface minimal and mobile-friendly.
type ntpProbeConfigResponse struct {
	Enabled        bool     `json:"enabled"`
	Servers        []string `json:"servers"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
}

// Get — GET /api/system/ntp-probe-config. Returns the live state from
// the time-health handler (post-PUT) which is the source of truth at
// runtime. Falls back to cfg.System if the handler hasn't been wired
// (defensive — should never happen in production).
func (h *SystemNTPProbeConfigHandler) Get(w http.ResponseWriter, _ *http.Request) {
	var opts ExternalNTPProbeOptions
	if h.timeH != nil {
		opts = h.timeH.ProbeOptions()
	} else {
		h.mu.Lock()
		opts = ExternalNTPProbeOptions{
			Enabled:   h.cfg.System.ExternalNTPProbeEnabled,
			Servers:   append([]string(nil), h.cfg.System.ExternalNTPServers...),
			PerServer: h.cfg.System.ExternalNTPProbeTimeout,
		}
		h.mu.Unlock()
	}
	timeoutSec := int(opts.PerServer / time.Second)
	if timeoutSec <= 0 {
		timeoutSec = 2
	}
	servers := opts.Servers
	if servers == nil {
		servers = []string{}
	}
	writeJSON(w, http.StatusOK, ntpProbeConfigResponse{
		Enabled:        opts.Enabled,
		Servers:        servers,
		TimeoutSeconds: timeoutSec,
	})
}

// ntpProbeConfigUpdateRequest is the body shape accepted by PUT.
//
// All fields are optional via pointer-to-T so the operator can flip a
// single dimension (e.g. just toggle Enabled without resetting the
// server list). An explicit empty `servers: []` clears the list.
type ntpProbeConfigUpdateRequest struct {
	Enabled        *bool     `json:"enabled,omitempty"`
	Servers        *[]string `json:"servers,omitempty"`
	TimeoutSeconds *int      `json:"timeoutSeconds,omitempty"`
}

// normalizeServers trims whitespace, drops empty entries, dedupes, and
// caps at MaxNTPProbeServers. Returns an error when the list contains
// more entries than the cap (after dedup) so a typo can't silently
// truncate operator intent.
func normalizeServers(in []string) ([]string, error) {
	if in == nil {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		key := strings.ToLower(s)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	if len(out) > MaxNTPProbeServers {
		return nil, fmt.Errorf("at most %d servers allowed (got %d)", MaxNTPProbeServers, len(out))
	}
	return out, nil
}

// Set — PUT /api/system/ntp-probe-config. Validates the partial body,
// mutates cfg.System in memory, persists the whole config, and pushes
// the new options into the live time-health handler. On disk-save
// failure the in-memory mutation is rolled back so readers don't
// diverge from disk.
func (h *SystemNTPProbeConfigHandler) Set(w http.ResponseWriter, r *http.Request) {
	var req ntpProbeConfigUpdateRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if req.Enabled == nil && req.Servers == nil && req.TimeoutSeconds == nil {
		writeError(w, http.StatusBadRequest, "body must contain at least one of: enabled, servers, timeoutSeconds")
		return
	}

	var newServers []string
	var err error
	if req.Servers != nil {
		newServers, err = normalizeServers(*req.Servers)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	var newTimeout time.Duration
	if req.TimeoutSeconds != nil {
		v := *req.TimeoutSeconds
		if v < NTPProbeMinTimeoutSeconds || v > NTPProbeMaxTimeoutSeconds {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("timeoutSeconds must be in [%d,%d]", NTPProbeMinTimeoutSeconds, NTPProbeMaxTimeoutSeconds))
			return
		}
		newTimeout = time.Duration(v) * time.Second
	}

	h.mu.Lock()
	prevEnabled := h.cfg.System.ExternalNTPProbeEnabled
	prevServers := append([]string(nil), h.cfg.System.ExternalNTPServers...)
	prevTimeout := h.cfg.System.ExternalNTPProbeTimeout

	if req.Enabled != nil {
		h.cfg.System.ExternalNTPProbeEnabled = *req.Enabled
	}
	if req.Servers != nil {
		h.cfg.System.ExternalNTPServers = newServers
	}
	if req.TimeoutSeconds != nil {
		h.cfg.System.ExternalNTPProbeTimeout = newTimeout
	}

	if saveErr := h.cfg.Save(); saveErr != nil {
		h.cfg.System.ExternalNTPProbeEnabled = prevEnabled
		h.cfg.System.ExternalNTPServers = prevServers
		h.cfg.System.ExternalNTPProbeTimeout = prevTimeout
		h.mu.Unlock()
		log.Error().Err(saveErr).Msg("ntp-probe-config: failed to persist update")
		writeError(w, http.StatusInternalServerError, "failed to persist config: "+saveErr.Error())
		return
	}

	// Snapshot the post-PUT state for the live push + the response.
	applied := ExternalNTPProbeOptions{
		Enabled:   h.cfg.System.ExternalNTPProbeEnabled,
		Servers:   append([]string(nil), h.cfg.System.ExternalNTPServers...),
		PerServer: h.cfg.System.ExternalNTPProbeTimeout,
	}
	onApply := h.onApply
	h.mu.Unlock()

	if h.timeH != nil {
		h.timeH.SetProbeOptions(applied)
	}
	if onApply != nil {
		onApply(applied)
	}

	log.Info().
		Bool("enabled", applied.Enabled).
		Int("servers", len(applied.Servers)).
		Dur("perServer", applied.PerServer).
		Msg("ntp-probe-config: updated")

	timeoutSec := int(applied.PerServer / time.Second)
	if timeoutSec <= 0 {
		timeoutSec = 2
	}
	servers := applied.Servers
	if servers == nil {
		servers = []string{}
	}
	writeJSON(w, http.StatusOK, ntpProbeConfigResponse{
		Enabled:        applied.Enabled,
		Servers:        servers,
		TimeoutSeconds: timeoutSec,
	})
}
