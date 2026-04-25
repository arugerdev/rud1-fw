// Package handlers — setup wizard NTP probe step.
//
// Endpoints:
//
//	GET  /api/setup/ntp/defaults — curated server list + timeout the
//	     wizard should pre-fill (mirrors the cloud panel's "use defaults"
//	     button).
//	POST /api/setup/ntp          — apply the wizard's NTP probe choice in
//	     a single round-trip: validates servers, persists to config.yaml,
//	     pushes the new options into the live time-health handler, and
//	     (optionally) runs an immediate probe so the wizard UI can show
//	     "✓ pool.ntp.org responded, drift +0.4s" before the operator clicks
//	     "Continue".
//
// Why a wizard-specific endpoint instead of reusing `PUT
// /api/system/ntp-probe-config`?
//
//   - The wizard runs unauthenticated (Setup.Complete=false) on the setup
//     AP. The runtime endpoint is bearer-gated. Splitting the routes lets
//     `SetupGate` cover the wizard step without weakening the runtime
//     surface.
//   - The wizard wants a one-click "use sensible defaults" affordance and
//     an immediate probe round-trip. The runtime endpoint is intentionally
//     minimal (just the persisted state).
//   - Audit action (`setup.ntp.set` vs `system.ntpProbe.update`) makes it
//     easy to filter wizard events out of the runtime change log.
//
// The handler intentionally lives next to setup.go so reset/general/
// complete/health can all see the same audit logger and mutex.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/audit/configlog"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/system/ntpprobe"
)

// DefaultSetupNTPServers is the curated list the wizard pre-fills when
// the operator clicks "use defaults". Three geographically-diverse public
// pools so a single outage doesn't poison the whole probe:
//
//   - pool.ntp.org   — community, anycast, the canonical fallback
//   - time.cloudflare.com — Cloudflare's anycast NTP, low-latency in EU
//   - time.google.com — Google's leap-smeared anycast (won't surprise the
//     monotonic clock during leap seconds)
//
// We deliberately keep this list to three: the wizard probe budget is
// small (`DefaultSetupNTPTimeoutSeconds × len`) and a longer list would
// just create UX noise without improving reachability.
var DefaultSetupNTPServers = []string{
	"pool.ntp.org",
	"time.cloudflare.com",
	"time.google.com",
}

// DefaultSetupNTPTimeoutSeconds is the per-server probe budget the wizard
// hands to operators when they pick "use defaults". 3s is long enough for
// a transatlantic round-trip on 4G, short enough that the wizard doesn't
// stall noticeably if the first server is unreachable.
const DefaultSetupNTPTimeoutSeconds = 3

// SetupNTPProbeApplier pushes the just-validated probe options into the
// live SystemTimeHealthHandler. The agent wires this to
// `sysTimeHealthH.SetProbeOptions`; tests pass a stub or nil.
type SetupNTPProbeApplier func(opts ExternalNTPProbeOptions)

// SetupNTPProber runs an immediate probe against the given server list
// using the per-server budget. The agent wires this to a thin wrapper
// around `ntpprobe.Query`; tests pass a stub. May return (nil, nil) when
// `enabled=false` to signal "no probe ran" without a synthetic error.
type SetupNTPProber func(ctx context.Context, servers []string, perServer time.Duration) (*ntpprobe.Result, error)

// setupNTPRequest is the body shape POST /api/setup/ntp accepts.
//
// `useDefaults`, when true and `servers` is empty, applies
// `DefaultSetupNTPServers`. When `servers` is set explicitly, the
// `useDefaults` flag is ignored (operator intent wins). `enabled` defaults
// to true on the wizard path — flipping it off in the wizard is unusual
// (why configure NTP servers and then disable the probe?) but allowed for
// the case where the operator wants to pre-stage the list and enable
// later from the cloud panel.
//
// `probe`, when true, runs an immediate one-shot probe before responding
// so the wizard UI can show a green tick. The probe runs even when the
// rest of the body is invalid? — no: validation runs first. A probe
// failure does NOT roll back the persistence — the operator may want the
// servers staged even if their LAN currently blocks UDP 123 (firewall
// fix is a separate step). The result is surfaced in the response so the
// UI can warn loudly.
type setupNTPRequest struct {
	Enabled        *bool     `json:"enabled,omitempty"`
	Servers        *[]string `json:"servers,omitempty"`
	TimeoutSeconds *int      `json:"timeoutSeconds,omitempty"`
	UseDefaults    bool      `json:"useDefaults,omitempty"`
	Probe          bool      `json:"probe,omitempty"`
}

// setupNTPProbeResult is the wire shape of an immediate probe result. All
// fields omitted when the request didn't ask for a probe.
type setupNTPProbeResult struct {
	Ran     bool    `json:"ran"`               // true when the request asked for a probe AND probing was attempted
	Ok      bool    `json:"ok"`                // true when the probe returned a result without error
	Server  string  `json:"server,omitempty"`  // server that responded first (when ok=true)
	SkewSec float64 `json:"skewSec,omitempty"` // signed seconds (server − local), 3-decimal precision
	RTTms   int64   `json:"rttMs,omitempty"`   // round-trip in milliseconds
	Error   string  `json:"error,omitempty"`   // probe error string when ok=false
}

// setupNTPResponse is what POST /api/setup/ntp returns. The applied block
// echoes the persisted state (so the UI doesn't need a follow-up GET) and
// `defaults` is included so the UI can render "you applied the defaults"
// vs "you applied a custom list" without a separate /defaults call.
type setupNTPResponse struct {
	Applied  ntpProbeConfigResponse `json:"applied"`
	Defaults setupNTPDefaults       `json:"defaults"`
	Probe    *setupNTPProbeResult   `json:"probe,omitempty"`
}

// setupNTPDefaults is the curated-defaults wire shape. Returned by both
// GET /api/setup/ntp/defaults (so the UI can pre-fill its textarea
// without a roundtrip through POST) and embedded in POST responses.
type setupNTPDefaults struct {
	Servers        []string `json:"servers"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
}

// SetSetupNTPHooks wires the live applier and prober into the SetupHandler.
// Both may be nil — callers that don't want immediate effects (tests,
// dev builds without a time-health handler) can leave them unset and the
// endpoint will still validate + persist correctly. The hooks live on
// SetupHandler (not SetupHandlerDeps) so the agent's wiring can attach
// them post-construction once the cross-handler graph is built (the
// time-health handler is created later than the setup handler).
func (h *SetupHandler) SetSetupNTPHooks(apply SetupNTPProbeApplier, prober SetupNTPProber) {
	h.mu.Lock()
	h.ntpApply = apply
	h.ntpProbe = prober
	h.mu.Unlock()
}

// NTPDefaults — GET /api/setup/ntp/defaults. Always returns the curated
// list; lives behind SetupGate so an unauthenticated wizard-time fetch
// works while a paired-device fetch requires the bearer.
func (h *SetupHandler) NTPDefaults(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, setupNTPDefaults{
		Servers:        append([]string(nil), DefaultSetupNTPServers...),
		TimeoutSeconds: DefaultSetupNTPTimeoutSeconds,
	})
}

// NTPApply — POST /api/setup/ntp. Validates → persists → pushes →
// (optionally) probes. On disk-save failure the in-memory mutation is
// rolled back so subsequent reads stay coherent with the YAML. The audit
// trail records the prev/next snapshot under action `setup.ntp.set`.
func (h *SetupHandler) NTPApply(w http.ResponseWriter, r *http.Request) {
	var req setupNTPRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	// Resolve "useDefaults" expansion before normalizeServers: when the
	// operator opted into defaults and didn't supply an explicit list,
	// we substitute the curated list. An explicit empty list (`servers:
	// []`) overrides useDefaults — operator intent wins.
	var serversInput *[]string
	switch {
	case req.Servers != nil:
		serversInput = req.Servers
	case req.UseDefaults:
		dup := append([]string(nil), DefaultSetupNTPServers...)
		serversInput = &dup
	}

	var newServers []string
	var err error
	if serversInput != nil {
		newServers, err = normalizeServers(*serversInput)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Timeout: if not provided AND useDefaults was requested, fall back
	// to DefaultSetupNTPTimeoutSeconds. Otherwise reuse whatever's
	// currently in cfg (may be the seeded default of 2s).
	var newTimeout time.Duration
	timeoutProvided := false
	switch {
	case req.TimeoutSeconds != nil:
		v := *req.TimeoutSeconds
		if v < NTPProbeMinTimeoutSeconds || v > NTPProbeMaxTimeoutSeconds {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("timeoutSeconds must be in [%d,%d]", NTPProbeMinTimeoutSeconds, NTPProbeMaxTimeoutSeconds))
			return
		}
		newTimeout = time.Duration(v) * time.Second
		timeoutProvided = true
	case req.UseDefaults:
		newTimeout = time.Duration(DefaultSetupNTPTimeoutSeconds) * time.Second
		timeoutProvided = true
	}

	// `enabled` default-on for the wizard. Without an explicit value
	// from the body we treat the wizard call as "I want the probe on";
	// callers who want to stage servers can pass `enabled: false` to
	// override.
	enabledProvided := req.Enabled != nil
	enabledNew := true
	if enabledProvided {
		enabledNew = *req.Enabled
	}

	h.mu.Lock()
	prevEnabled := h.cfg.System.ExternalNTPProbeEnabled
	prevServers := append([]string(nil), h.cfg.System.ExternalNTPServers...)
	prevTimeout := h.cfg.System.ExternalNTPProbeTimeout
	prevSnap := setupNTPAuditSnapshot(prevEnabled, prevServers, prevTimeout)

	// Apply. We always set Enabled (the wizard's default is "on") and
	// only touch servers/timeout when the operator gave us new values.
	h.cfg.System.ExternalNTPProbeEnabled = enabledNew
	if serversInput != nil {
		h.cfg.System.ExternalNTPServers = newServers
	}
	if timeoutProvided {
		h.cfg.System.ExternalNTPProbeTimeout = newTimeout
	}

	auditL := h.auditLog
	if saveErr := h.cfg.Save(); saveErr != nil {
		h.cfg.System.ExternalNTPProbeEnabled = prevEnabled
		h.cfg.System.ExternalNTPServers = prevServers
		h.cfg.System.ExternalNTPProbeTimeout = prevTimeout
		h.mu.Unlock()
		log.Error().Err(saveErr).Msg("setup.ntp.set: failed to persist update")
		if auditL != nil {
			if err := auditL.Append(r.Context(), configlog.Entry{
				Action:   "setup.ntp.set",
				Actor:    "operator",
				Previous: prevSnap,
				Next:     nil,
				OK:       false,
				Error:    "save: " + saveErr.Error(),
			}); err != nil {
				log.Warn().Err(err).Msg("audit append failed (non-fatal)")
			}
		}
		writeError(w, http.StatusInternalServerError, "failed to persist NTP probe config: "+saveErr.Error())
		return
	}

	applied := ExternalNTPProbeOptions{
		Enabled:   h.cfg.System.ExternalNTPProbeEnabled,
		Servers:   append([]string(nil), h.cfg.System.ExternalNTPServers...),
		PerServer: h.cfg.System.ExternalNTPProbeTimeout,
	}
	nextSnap := setupNTPAuditSnapshot(applied.Enabled, applied.Servers, applied.PerServer)
	apply := h.ntpApply
	prober := h.ntpProbe
	h.mu.Unlock()

	if auditL != nil {
		if err := auditL.Append(r.Context(), configlog.Entry{
			Action:   "setup.ntp.set",
			Actor:    "operator",
			Previous: prevSnap,
			Next:     nextSnap,
			OK:       true,
		}); err != nil {
			log.Warn().Err(err).Msg("audit append failed (non-fatal)")
		}
	}

	if apply != nil {
		apply(applied)
	}

	resp := setupNTPResponse{
		Applied: ntpProbeResponseFromOptions(applied),
		Defaults: setupNTPDefaults{
			Servers:        append([]string(nil), DefaultSetupNTPServers...),
			TimeoutSeconds: DefaultSetupNTPTimeoutSeconds,
		},
	}

	if req.Probe {
		probeRes := runSetupNTPProbe(r.Context(), prober, applied)
		resp.Probe = &probeRes
	}

	log.Info().
		Bool("enabled", applied.Enabled).
		Int("servers", len(applied.Servers)).
		Dur("perServer", applied.PerServer).
		Bool("probe", req.Probe).
		Msg("setup.ntp.set: applied")

	writeJSON(w, http.StatusOK, resp)
}

// runSetupNTPProbe encapsulates the immediate-probe behaviour:
//
//   - probe disabled / no servers / no prober wired → ran=false, no error
//   - prober returns error → ran=true, ok=false, error preserved
//   - prober returns result → ran=true, ok=true, server/skew/rtt set
//
// The probe runs under a tight outer ctx (the request's) so a slow probe
// can't outlive the wizard call. The per-server budget is what the
// operator just persisted (or the default if they didn't touch it).
func runSetupNTPProbe(ctx context.Context, prober SetupNTPProber, applied ExternalNTPProbeOptions) setupNTPProbeResult {
	if !applied.Enabled || len(applied.Servers) == 0 || prober == nil {
		return setupNTPProbeResult{Ran: false}
	}
	res, err := prober(ctx, applied.Servers, applied.PerServer)
	if err != nil || res == nil {
		msg := "no result"
		if err != nil {
			msg = err.Error()
		}
		return setupNTPProbeResult{Ran: true, Ok: false, Error: msg}
	}
	return setupNTPProbeResult{
		Ran:     true,
		Ok:      true,
		Server:  res.Server,
		SkewSec: roundSkewSeconds(res.Skew),
		RTTms:   res.RTT.Milliseconds(),
	}
}

// roundSkewSeconds matches the rounding used by /api/system/time-health
// (3 decimal places). Defined locally to avoid a cross-handler import
// cycle and to keep the wire shape predictable for the wizard's UI.
func roundSkewSeconds(d time.Duration) float64 {
	const factor = 1000.0
	v := d.Seconds() * factor
	if v >= 0 {
		return float64(int64(v+0.5)) / factor
	}
	return float64(int64(v-0.5)) / factor
}

// ntpProbeResponseFromOptions converts the in-memory option struct into
// the JSON wire shape shared with PUT /api/system/ntp-probe-config so the
// wizard and the runtime page render the same panel. Servers is cloned;
// nil collapses to `[]` (UI never deals with `null`).
func ntpProbeResponseFromOptions(opts ExternalNTPProbeOptions) ntpProbeConfigResponse {
	timeoutSec := int(opts.PerServer / time.Second)
	if timeoutSec <= 0 {
		timeoutSec = 2
	}
	servers := opts.Servers
	if servers == nil {
		servers = []string{}
	}
	return ntpProbeConfigResponse{
		Enabled:        opts.Enabled,
		Servers:        servers,
		TimeoutSeconds: timeoutSec,
	}
}

// setupNTPAuditSnapshot mirrors ntpProbeAuditSnapshot but namespaces the
// keys identically so a future audit reader can diff a `setup.ntp.set`
// entry against a `system.ntpProbe.update` entry side-by-side.
func setupNTPAuditSnapshot(enabled bool, servers []string, perServer time.Duration) map[string]any {
	out := make([]string, len(servers))
	copy(out, servers)
	timeoutSec := int(perServer / time.Second)
	if timeoutSec <= 0 {
		timeoutSec = 2
	}
	return map[string]any{
		"enabled":        enabled,
		"servers":        out,
		"timeoutSeconds": timeoutSec,
	}
}

// Compile-time guard: SetupNTPProber's signature must stay aligned with
// ntpprobe.Query so the agent can wire it directly without an adapter.
// If Query's signature ever changes, this assignment will fail and we
// know to revisit the SetupHandler hook.
var _ SetupNTPProber = func(ctx context.Context, servers []string, perServer time.Duration) (*ntpprobe.Result, error) {
	return ntpprobe.Query(ctx, servers, perServer, nil)
}

// SetupConfigPtr is exposed so future setup-wizard sub-handlers can
// safely read SetupConfig fields under the same mutex without copying
// the entire snapshot. Currently unused outside this file but kept here
// to avoid leaking a setter.
type SetupConfigPtr = config.SetupConfig
