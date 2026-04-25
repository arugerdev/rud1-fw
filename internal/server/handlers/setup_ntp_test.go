package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/system/ntpprobe"
)

// newSetupNTPRouter wires the chi routes the iter-35 wizard exposes
// (alongside state/general/complete/health/reset) so the request matches
// the production layout. Returns the router, the cfg backing the
// handler, and the handler itself so individual tests can poke at hook
// counters or live state.
func newSetupNTPRouter(t *testing.T, token string) (*chi.Mux, *config.Config, *SetupHandler) {
	t.Helper()
	cfg := freshCfg(t)
	h := NewSetupHandler(cfg, SetupHandlerDeps{
		SerialNumber: func() string { return "RUD1-NTP" },
	})
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(SetupGate(cfg, token))
		r.Get("/api/setup/state", h.State)
		r.Get("/api/setup/health", h.Health)
		r.Post("/api/setup/general", h.General)
		r.Post("/api/setup/complete", h.Complete)
		r.Get("/api/setup/ntp/defaults", h.NTPDefaults)
		r.Post("/api/setup/ntp", h.NTPApply)
	})
	return r, cfg, h
}

// TestSetupNTP_DefaultsReturnsCuratedList: the curated /defaults endpoint
// surfaces the same constants used by the wizard's "use defaults" button.
// Validates that the wire shape matches setupNTPDefaults so the local
// panel can pre-fill its textarea without a roundtrip through POST.
func TestSetupNTP_DefaultsReturnsCuratedList(t *testing.T) {
	r, _, _ := newSetupNTPRouter(t, "")

	req := httptest.NewRequest(http.MethodGet, "/api/setup/ntp/defaults", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	var got setupNTPDefaults
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.TimeoutSeconds != DefaultSetupNTPTimeoutSeconds {
		t.Fatalf("timeoutSeconds = %d, want %d", got.TimeoutSeconds, DefaultSetupNTPTimeoutSeconds)
	}
	if len(got.Servers) != len(DefaultSetupNTPServers) {
		t.Fatalf("len(servers) = %d, want %d", len(got.Servers), len(DefaultSetupNTPServers))
	}
	for i, want := range DefaultSetupNTPServers {
		if got.Servers[i] != want {
			t.Fatalf("servers[%d] = %q, want %q", i, got.Servers[i], want)
		}
	}
}

// TestSetupNTP_UseDefaultsAppliesCuratedList: posting `useDefaults:true`
// without a `servers` field expands to the curated list, persists, and
// flips Enabled on by default. Verifies the rolled-out cfg matches and
// that the timeout snaps to DefaultSetupNTPTimeoutSeconds.
func TestSetupNTP_UseDefaultsAppliesCuratedList(t *testing.T) {
	r, cfg, _ := newSetupNTPRouter(t, "")

	body := bytes.NewReader([]byte(`{"useDefaults":true}`))
	req := httptest.NewRequest(http.MethodPost, "/api/setup/ntp", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	if !cfg.System.ExternalNTPProbeEnabled {
		t.Fatalf("Enabled=false, want true (wizard default)")
	}
	if got, want := len(cfg.System.ExternalNTPServers), len(DefaultSetupNTPServers); got != want {
		t.Fatalf("len(servers) = %d, want %d", got, want)
	}
	if cfg.System.ExternalNTPProbeTimeout != time.Duration(DefaultSetupNTPTimeoutSeconds)*time.Second {
		t.Fatalf("timeout = %s, want %ds", cfg.System.ExternalNTPProbeTimeout, DefaultSetupNTPTimeoutSeconds)
	}

	var got setupNTPResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Applied.Enabled || len(got.Applied.Servers) != 3 {
		t.Fatalf("applied = %+v, want enabled=true with 3 servers", got.Applied)
	}
	if got.Applied.TimeoutSeconds != DefaultSetupNTPTimeoutSeconds {
		t.Fatalf("applied.timeoutSeconds = %d, want %d", got.Applied.TimeoutSeconds, DefaultSetupNTPTimeoutSeconds)
	}
	if got.Probe != nil {
		t.Fatalf("probe = %+v, want nil (request didn't ask for one)", got.Probe)
	}
}

// TestSetupNTP_ExplicitServersOverrideUseDefaults: when both useDefaults
// AND servers are present, operator intent (servers) wins. Curated
// defaults are not substituted.
func TestSetupNTP_ExplicitServersOverrideUseDefaults(t *testing.T) {
	r, cfg, _ := newSetupNTPRouter(t, "")

	body := bytes.NewReader([]byte(`{"useDefaults":true,"servers":["ntp.example.com"],"timeoutSeconds":5}`))
	req := httptest.NewRequest(http.MethodPost, "/api/setup/ntp", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	if got := cfg.System.ExternalNTPServers; len(got) != 1 || got[0] != "ntp.example.com" {
		t.Fatalf("servers = %v, want [ntp.example.com]", got)
	}
	if cfg.System.ExternalNTPProbeTimeout != 5*time.Second {
		t.Fatalf("timeout = %s, want 5s", cfg.System.ExternalNTPProbeTimeout)
	}
}

// TestSetupNTP_ExplicitEmptyServersClearsList: an explicit `[]` is the
// "I really want no servers" signal. useDefaults must NOT silently
// substitute the curated list when the operator was explicit.
func TestSetupNTP_ExplicitEmptyServersClearsList(t *testing.T) {
	r, cfg, _ := newSetupNTPRouter(t, "")
	cfg.System.ExternalNTPServers = []string{"old.example.com"}

	body := bytes.NewReader([]byte(`{"useDefaults":true,"servers":[]}`))
	req := httptest.NewRequest(http.MethodPost, "/api/setup/ntp", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	if len(cfg.System.ExternalNTPServers) != 0 {
		t.Fatalf("servers = %v, want empty (explicit [] wins over useDefaults)", cfg.System.ExternalNTPServers)
	}
}

// TestSetupNTP_TimeoutOutOfBoundsRejected: 0s and 31s both 400.
func TestSetupNTP_TimeoutOutOfBoundsRejected(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"zero", `{"useDefaults":true,"timeoutSeconds":0}`},
		{"too_high", `{"useDefaults":true,"timeoutSeconds":31}`},
		{"negative", `{"useDefaults":true,"timeoutSeconds":-1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _, _ := newSetupNTPRouter(t, "")
			req := httptest.NewRequest(http.MethodPost, "/api/setup/ntp", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 — body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

// TestSetupNTP_TooManyServersRejected: passing more than
// MaxNTPProbeServers entries (after dedup) returns 400 and DOES NOT
// mutate cfg — the validation runs before persistence.
func TestSetupNTP_TooManyServersRejected(t *testing.T) {
	r, cfg, _ := newSetupNTPRouter(t, "")
	cfg.System.ExternalNTPServers = []string{"keep.example.com"}

	too := make([]string, MaxNTPProbeServers+2)
	for i := range too {
		too[i] = "host" + string(rune('a'+i)) + ".example.com"
	}
	payload, _ := json.Marshal(map[string]any{"servers": too})

	req := httptest.NewRequest(http.MethodPost, "/api/setup/ntp", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — body=%s", rr.Code, rr.Body.String())
	}
	if got := cfg.System.ExternalNTPServers; len(got) != 1 || got[0] != "keep.example.com" {
		t.Fatalf("cfg mutated despite validation failure: %v", got)
	}
}

// TestSetupNTP_ProbeRunsAndReportsResult wires a stub prober that returns
// a deterministic skew + RTT, asks for `probe:true`, and verifies the
// response carries the probe block with rounded skew. Also asserts the
// applier was called exactly once with the persisted options.
func TestSetupNTP_ProbeRunsAndReportsResult(t *testing.T) {
	r, _, h := newSetupNTPRouter(t, "")

	var applyCount int
	var lastApplied ExternalNTPProbeOptions
	apply := func(opts ExternalNTPProbeOptions) {
		applyCount++
		lastApplied = opts
	}
	prober := func(_ context.Context, servers []string, _ time.Duration) (*ntpprobe.Result, error) {
		if len(servers) == 0 {
			t.Fatalf("prober called with empty server list")
		}
		return &ntpprobe.Result{
			Server: servers[0],
			Skew:   1234 * time.Millisecond, // 1.234s
			RTT:    42 * time.Millisecond,
		}, nil
	}
	h.SetSetupNTPHooks(apply, prober)

	body := bytes.NewReader([]byte(`{"useDefaults":true,"probe":true}`))
	req := httptest.NewRequest(http.MethodPost, "/api/setup/ntp", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	if applyCount != 1 {
		t.Fatalf("applier called %d times, want 1", applyCount)
	}
	if !lastApplied.Enabled || len(lastApplied.Servers) != 3 {
		t.Fatalf("applier saw %+v, want enabled=true with 3 servers", lastApplied)
	}

	var got setupNTPResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Probe == nil {
		t.Fatalf("probe block missing")
	}
	if !got.Probe.Ran || !got.Probe.Ok {
		t.Fatalf("probe = %+v, want ran=true ok=true", got.Probe)
	}
	if got.Probe.SkewSec != 1.234 {
		t.Fatalf("probe.skewSec = %v, want 1.234", got.Probe.SkewSec)
	}
	if got.Probe.RTTms != 42 {
		t.Fatalf("probe.rttMs = %d, want 42", got.Probe.RTTms)
	}
	if got.Probe.Server == "" {
		t.Fatalf("probe.server empty, want first curated default")
	}
}

// TestSetupNTP_ProbeFailureDoesNotRollBack persists the new servers even
// when the immediate probe round-trip fails — operator intent (the
// stored config) is independent of the immediate-probe diagnostic. The
// probe error is surfaced in the response so the wizard UI can warn.
func TestSetupNTP_ProbeFailureDoesNotRollBack(t *testing.T) {
	r, cfg, h := newSetupNTPRouter(t, "")

	probeErr := errors.New("udp blocked by firewall")
	h.SetSetupNTPHooks(nil, func(_ context.Context, _ []string, _ time.Duration) (*ntpprobe.Result, error) {
		return nil, probeErr
	})

	body := bytes.NewReader([]byte(`{"useDefaults":true,"probe":true}`))
	req := httptest.NewRequest(http.MethodPost, "/api/setup/ntp", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	if !cfg.System.ExternalNTPProbeEnabled || len(cfg.System.ExternalNTPServers) != 3 {
		t.Fatalf("cfg rolled back on probe failure: enabled=%v servers=%v", cfg.System.ExternalNTPProbeEnabled, cfg.System.ExternalNTPServers)
	}

	var got setupNTPResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Probe == nil || got.Probe.Ok {
		t.Fatalf("probe = %+v, want ran=true ok=false", got.Probe)
	}
	if got.Probe.Error != probeErr.Error() {
		t.Fatalf("probe.error = %q, want %q", got.Probe.Error, probeErr.Error())
	}
}

// TestSetupNTP_ProbeSkippedWhenDisabled: if the operator pushes
// `enabled:false`, the immediate-probe block reports ran=false even
// when probe:true was requested — there's no point dialling out for a
// configuration the operator just turned off.
func TestSetupNTP_ProbeSkippedWhenDisabled(t *testing.T) {
	r, _, h := newSetupNTPRouter(t, "")

	probeCalls := 0
	h.SetSetupNTPHooks(nil, func(_ context.Context, _ []string, _ time.Duration) (*ntpprobe.Result, error) {
		probeCalls++
		return &ntpprobe.Result{Skew: time.Second}, nil
	})

	body := bytes.NewReader([]byte(`{"useDefaults":true,"enabled":false,"probe":true}`))
	req := httptest.NewRequest(http.MethodPost, "/api/setup/ntp", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	if probeCalls != 0 {
		t.Fatalf("prober called %d times, want 0 (probe disabled)", probeCalls)
	}

	var got setupNTPResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Probe == nil || got.Probe.Ran {
		t.Fatalf("probe = %+v, want ran=false", got.Probe)
	}
}

// TestSetupNTP_GateLocksDownPostComplete mirrors the
// CompleteFlipsAndLocksDownEndpoints test: once Setup.Complete=true,
// /api/setup/ntp must reject calls without a bearer.
func TestSetupNTP_GateLocksDownPostComplete(t *testing.T) {
	const token = "secret"
	r, cfg, _ := newSetupNTPRouter(t, token)
	cfg.Setup.Complete = true

	req := httptest.NewRequest(http.MethodPost, "/api/setup/ntp",
		strings.NewReader(`{"useDefaults":true}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}

	authReq := httptest.NewRequest(http.MethodPost, "/api/setup/ntp",
		strings.NewReader(`{"useDefaults":true}`))
	authReq.Header.Set("Content-Type", "application/json")
	authReq.Header.Set("Authorization", "Bearer "+token)
	ar := httptest.NewRecorder()
	r.ServeHTTP(ar, authReq)
	if ar.Code != http.StatusOK {
		t.Fatalf("with bearer: status = %d (body=%s)", ar.Code, ar.Body.String())
	}
}

// TestSetupNTP_RoundSkewSeconds covers the rounding helper used to align
// the wizard's wire shape with the time-health response: positive and
// negative skews both round to 3 decimals away-from-zero.
func TestSetupNTP_RoundSkewSeconds(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want float64
	}{
		{1234 * time.Millisecond, 1.234},
		{-1234 * time.Millisecond, -1.234},
		{1234567 * time.Microsecond, 1.235},   // 1.234567 → 1.235
		{-1234567 * time.Microsecond, -1.235}, // away from zero
		{0, 0},
	}
	for _, tc := range cases {
		got := roundSkewSeconds(tc.in)
		if got != tc.want {
			t.Fatalf("roundSkewSeconds(%s) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
