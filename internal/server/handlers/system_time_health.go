// Package handlers — system clock health endpoint.
//
// Endpoints:
//
//	GET /api/system/time-health — operator-friendly summary of TZ + NTP state
//
// The first-boot wizard sets a timezone, but a fresh Pi may still be running
// on UTC if the operator skipped the step. Likewise a Pi that loses internet
// during install may have systemd-timesyncd stuck without a peer, leaving
// log timestamps drifting. Both conditions are silent in the existing
// /api/system/health snapshot, so rud1-app needs a dedicated tile to surface
// them. Read-only, sub-100ms in normal operation, degrades gracefully when
// timedatectl/systemctl are absent (Windows dev, minimal containers).
package handlers

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/system/ntpprobe"
	"github.com/rud1-es/rud1-fw/internal/platform"
)

// ClockSkewWarnThresholdSeconds is the absolute drift (in seconds) above
// which we surface a warning for the operator. 30s matches systemd-
// timesyncd's own "huge" threshold and is well past the worst-case skew
// a well-functioning NTP-disciplined clock should ever exhibit.
const ClockSkewWarnThresholdSeconds = 30.0

// ExternalNTPProbeOptions configures the optional outbound NTP probe used
// to detect a drifted RTC after power loss. The probe is OFF by default —
// callers (the agent's wiring) explicitly opt the device in via config.
//
// Servers are tried in order; the first to respond within PerServer
// timeout wins. ProbeNow is overridable so tests can drive a known
// fixture without going through the network.
type ExternalNTPProbeOptions struct {
	Enabled   bool
	Servers   []string
	PerServer time.Duration
	// ProbeNow is the injection point for tests. Production code leaves
	// it nil and the handler dials over UDP via ntpprobe.Query. The
	// signature deliberately matches a thin wrapper around Query so
	// the test stub stays trivially short.
	ProbeNow func(ctx context.Context, servers []string, perServer time.Duration) (*ntpprobe.Result, error)
}

// SystemTimeHealthHandler — wired by server.go with optional NTP-probe
// settings. The zero-value (empty options) keeps the legacy behaviour:
// the handler returns the same response shape, simply without the
// `clockSkewSeconds` field populated.
type SystemTimeHealthHandler struct {
	probe ExternalNTPProbeOptions
}

// NewSystemTimeHealthHandler builds the handler with no external probe.
// Used by callers that don't want the extra outbound query (or that
// want to keep the endpoint cheap by default — the per-request budget
// stays sub-100ms when no probe runs).
func NewSystemTimeHealthHandler() *SystemTimeHealthHandler {
	return &SystemTimeHealthHandler{}
}

// NewSystemTimeHealthHandlerWithProbe is the agent-facing constructor:
// it threads through `cfg.System.ExternalNTPProbe*` so the operator
// gets a `clockSkewSeconds` figure on every snapshot.
//
// When opts.Enabled is false this is equivalent to
// NewSystemTimeHealthHandler — the absence of servers is treated as a
// no-op rather than a configuration error so flipping the flag back
// off in YAML doesn't require restarting the agent twice.
func NewSystemTimeHealthHandlerWithProbe(opts ExternalNTPProbeOptions) *SystemTimeHealthHandler {
	if opts.PerServer <= 0 {
		opts.PerServer = 2 * time.Second
	}
	return &SystemTimeHealthHandler{probe: opts}
}

// timesyncdState is the parsed verdict for systemd-timesyncd. We expose the
// raw `ActiveState` so a future UI revision can show "activating" without a
// schema change, but pre-bake an `ok` boolean for the common case.
type timesyncdState struct {
	OK          bool   `json:"ok"`
	ActiveState string `json:"activeState"` // "active"/"inactive"/"failed"/"activating"/"unknown"
	SubState    string `json:"subState"`    // "running"/"dead"/"failed"/"unknown"
}

// systemTimeHealthResponse is the JSON returned by TimeHealth. Every
// sub-field is structured so the UI doesn't have to parse strings: the
// `warnings` array is the human-readable summary an operator can glance at
// without expanding.
type systemTimeHealthResponse struct {
	Now             int64           `json:"now"`              // unix seconds at the time the response was assembled
	Timezone        string          `json:"timezone"`         // current TZ name
	TimezoneSource  string          `json:"timezoneSource"`   // "timedatectl"|"etc_localtime"|"tz_env"|"fallback"
	UTCOffset       int             `json:"utcOffsetSeconds"` // signed seconds east of UTC
	IsUTC           bool            `json:"isUTC"`            // true ⇔ timezone resolves to UTC (or unset)
	NTPSynchronized bool            `json:"ntpSynchronized"`  // timedatectl `NTPSynchronized=yes`
	NTPEnabled      bool            `json:"ntpEnabled"`       // timedatectl `NTP=yes` (operator opted in)
	Timesyncd       *timesyncdState `json:"timesyncd"`        // nil when systemctl is unavailable
	Simulated       bool            `json:"simulated"`        // true on dev hardware (no timedatectl/systemctl)
	// ClockSkewSeconds is the signed difference (server − local) measured
	// against the configured external NTP server, rounded to 3 decimals.
	// Pointer-typed so the field is omitted from the JSON when the probe
	// is disabled (default) OR when every configured server failed —
	// keeping the endpoint cheap by default and unambiguous on failure.
	ClockSkewSeconds *float64 `json:"clockSkewSeconds,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

// TimeHealth — GET /api/system/time-health.
//
// On real hardware we shell out to `timedatectl show` (one round-trip,
// machine-readable key=value output) and `systemctl show systemd-timesyncd`
// for the activation state. Both shells are bounded by a 3s context; if
// either fails we degrade to a partial response and surface the failure as
// a warning so operators don't have to grep journald to diagnose.
func (h *SystemTimeHealthHandler) TimeHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	resp := snapshotTimeHealth(ctx, h.probe)
	writeJSON(w, http.StatusOK, resp)
}

// snapshotTimeHealth assembles the same response object the HTTP handler
// returns, but as a pure call so other in-process subsystems (notably the
// heartbeat builder in the agent package) can reuse it without dialing
// localhost. The caller is responsible for picking an appropriate context
// timeout — this function does not impose one of its own so a tight 1s
// heartbeat budget can coexist with the 3s HTTP budget.
func snapshotTimeHealth(ctx context.Context, probe ExternalNTPProbeOptions) systemTimeHealthResponse {
	current, source := readCurrentTimezone()
	_, offset := time.Now().Zone()

	resp := systemTimeHealthResponse{
		Now:            time.Now().Unix(),
		Timezone:       current,
		TimezoneSource: source,
		UTCOffset:      offset,
		IsUTC:          isEffectivelyUTC(current),
		Simulated:      platform.SimulateHardware() || !platform.IsLinux(),
	}

	if !resp.Simulated {
		ntp, ntpEnabled, err := readNTPStatus(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("time health: timedatectl show failed")
			resp.Warnings = append(resp.Warnings, "timedatectl unavailable: "+err.Error())
		} else {
			resp.NTPSynchronized = ntp
			resp.NTPEnabled = ntpEnabled
		}
		ts, err := readTimesyncdState(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("time health: systemctl show systemd-timesyncd failed")
			resp.Warnings = append(resp.Warnings, "systemctl unavailable: "+err.Error())
		} else {
			resp.Timesyncd = ts
		}
	}

	if resp.IsUTC && source == "fallback" {
		resp.Warnings = append(resp.Warnings,
			"timezone is the UTC fallback — set the device timezone in Settings if the operator is in a non-UTC region")
	}
	if !resp.Simulated && resp.NTPEnabled && !resp.NTPSynchronized {
		resp.Warnings = append(resp.Warnings,
			"NTP is enabled but the clock is not yet synchronized — check internet reachability")
	}
	if resp.Timesyncd != nil && !resp.Timesyncd.OK && resp.Timesyncd.ActiveState != "" {
		resp.Warnings = append(resp.Warnings,
			"systemd-timesyncd is "+resp.Timesyncd.ActiveState+" ("+resp.Timesyncd.SubState+")")
	}

	// External NTP probe (opt-in). Runs LAST so its warning sits next to
	// the other clock-related ones, and so a probe failure can't suppress
	// the rest of the response. We swallow probe errors as a debug log:
	// the absence of `clockSkewSeconds` in the response is itself the
	// signal that the probe didn't yield a result this tick.
	if probe.Enabled && len(probe.Servers) > 0 {
		if skew, server, ok := runClockSkewProbe(ctx, probe); ok {
			rounded := math.Round(skew*1000) / 1000
			resp.ClockSkewSeconds = &rounded
			if math.Abs(rounded) > ClockSkewWarnThresholdSeconds {
				resp.Warnings = append(resp.Warnings,
					fmt.Sprintf("clock skew exceeds %ds vs NTP server %s",
						int(ClockSkewWarnThresholdSeconds), server))
			}
		}
	}

	return resp
}

// runClockSkewProbe is the thin wrapper between snapshotTimeHealth and
// the ntpprobe package. Lifted out so the test stub in
// ExternalNTPProbeOptions.ProbeNow can be invoked here without
// duplicating the rounding/threshold logic above.
func runClockSkewProbe(ctx context.Context, probe ExternalNTPProbeOptions) (skew float64, server string, ok bool) {
	per := probe.PerServer
	if per <= 0 {
		per = 2 * time.Second
	}
	probeFn := probe.ProbeNow
	if probeFn == nil {
		probeFn = func(ctx context.Context, servers []string, perServer time.Duration) (*ntpprobe.Result, error) {
			return ntpprobe.Query(ctx, servers, perServer, nil)
		}
	}
	res, err := probeFn(ctx, probe.Servers, per)
	if err != nil {
		log.Debug().Err(err).Msg("time health: external NTP probe failed")
		return 0, "", false
	}
	if res == nil {
		return 0, "", false
	}
	return res.Skew.Seconds(), res.Server, true
}

// TimeHealthSnapshot is the public, in-process entry point for the
// time-health response. It mirrors the GET /api/system/time-health handler
// but returns a structured value instead of writing JSON. The agent uses
// this to populate the heartbeat's `timeHealth` block without going
// through HTTP.
//
// The returned value is the same shape as the JSON response — including
// the `simulated` / `now` / `utcOffsetSeconds` fields the agent
// deliberately drops on the wire. Callers should project to the smaller
// `cloud.HBTimeHealth` shape themselves.
//
// `probe` mirrors the agent-side configuration for the external NTP
// probe. Pass the zero value to skip the probe entirely (cheap default
// that keeps the snapshot under 100ms).
func TimeHealthSnapshot(ctx context.Context, probe ExternalNTPProbeOptions) TimeHealthResponse {
	return snapshotTimeHealth(ctx, probe)
}

// TimeHealthResponse is the exported alias of the wire response struct,
// exposed so other packages can read fields without re-parsing JSON.
// Field semantics are documented on systemTimeHealthResponse.
type TimeHealthResponse = systemTimeHealthResponse

// isEffectivelyUTC returns true when the resolved timezone is UTC or one of
// the "I haven't been configured" placeholders. Catches `Etc/UTC` on Debian
// minimal images and the empty fallback.
func isEffectivelyUTC(tz string) bool {
	switch strings.TrimSpace(tz) {
	case "UTC", "Etc/UTC", "Universal", "Zulu", "":
		return true
	}
	return false
}

// readNTPStatus invokes `timedatectl show --property=NTP --property=NTPSynchronized`
// and parses the key=value output. Returns (synced, enabled, err).
//
// Sample output:
//
//	NTP=yes
//	NTPSynchronized=yes
func readNTPStatus(ctx context.Context) (synced, enabled bool, err error) {
	cmd := exec.CommandContext(ctx, "timedatectl", "show",
		"--property=NTP",
		"--property=NTPSynchronized")
	out, runErr := cmd.Output()
	if runErr != nil {
		return false, false, runErr
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "NTP":
			enabled = strings.EqualFold(strings.TrimSpace(val), "yes")
		case "NTPSynchronized":
			synced = strings.EqualFold(strings.TrimSpace(val), "yes")
		}
	}
	return synced, enabled, nil
}

// readTimesyncdState invokes `systemctl show systemd-timesyncd
// --property=ActiveState --property=SubState` and maps the verdict to our
// `ok` boolean. "active/running" is OK; anything else (failed, activating
// stuck, masked) is not.
func readTimesyncdState(ctx context.Context) (*timesyncdState, error) {
	cmd := exec.CommandContext(ctx, "systemctl", "show", "systemd-timesyncd",
		"--property=ActiveState",
		"--property=SubState")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	state := &timesyncdState{ActiveState: "unknown", SubState: "unknown"}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.TrimSpace(key) {
		case "ActiveState":
			if val != "" {
				state.ActiveState = val
			}
		case "SubState":
			if val != "" {
				state.SubState = val
			}
		}
	}
	state.OK = state.ActiveState == "active" && state.SubState == "running"
	return state, nil
}
