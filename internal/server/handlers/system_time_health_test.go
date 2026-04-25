package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/system/ntpprobe"
)

func newTimeHealthRouter(h *SystemTimeHealthHandler) *chi.Mux {
	r := chi.NewRouter()
	r.Get("/api/system/time-health", h.TimeHealth)
	return r
}

// TestSystemTimeHealth_RespondsOK: on dev hardware (no timedatectl/systemctl)
// the handler must still return 200 with a structurally-valid envelope. The
// `simulated` flag tells the UI not to interpret missing NTP fields as a
// failure.
func TestSystemTimeHealth_RespondsOK(t *testing.T) {
	h := NewSystemTimeHealthHandler()
	r := newTimeHealthRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/system/time-health", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}

	var got systemTimeHealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Now <= 0 {
		t.Fatalf("now=%d, want positive unix seconds", got.Now)
	}
	if got.Timezone == "" {
		t.Fatalf("timezone=empty, want non-empty (UTC fallback at minimum)")
	}
	if got.TimezoneSource == "" {
		t.Fatalf("timezoneSource=empty, want one of timedatectl/etc_localtime/tz_env/fallback")
	}
}

// TestIsEffectivelyUTC: the helper backs the IsUTC field on the wire and
// gates a warning. The "default-not-yet-configured" placeholders all map
// to true; anything else is non-UTC even if its UTC offset is zero (e.g.
// Atlantic/Reykjavik is GMT year-round but is NOT a UTC fallback).
func TestIsEffectivelyUTC(t *testing.T) {
	cases := map[string]bool{
		"":                   true,
		"UTC":                true,
		"Etc/UTC":            true,
		"Universal":          true,
		"Zulu":               true,
		"Europe/Madrid":      false,
		"America/New_York":   false,
		"Atlantic/Reykjavik": false,
	}
	for in, want := range cases {
		got := isEffectivelyUTC(in)
		if got != want {
			t.Errorf("isEffectivelyUTC(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestSystemTimeHealth_RespondsOKWithClockSkew: when the optional outbound
// NTP probe is enabled and the stub returns a planted skew, the handler
// MUST surface it in `clockSkewSeconds` (rounded to 3 decimals) and emit
// the standard "skew exceeds threshold" warning when |skew| crosses the
// configured threshold. The probe is wired with a deterministic stub so
// the test never touches the network.
func TestSystemTimeHealth_RespondsOKWithClockSkew(t *testing.T) {
	planted := 42.5 // > 30s threshold so the warning fires
	probe := ExternalNTPProbeOptions{
		Enabled:   true,
		Servers:   []string{"stub.ntp.invalid"},
		PerServer: time.Second,
		ProbeNow: func(ctx context.Context, servers []string, perServer time.Duration) (*ntpprobe.Result, error) {
			return &ntpprobe.Result{
				Server: servers[0],
				Skew:   time.Duration(planted * float64(time.Second)),
			}, nil
		},
	}
	h := NewSystemTimeHealthHandlerWithProbe(probe)
	r := newTimeHealthRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/system/time-health", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	var got systemTimeHealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ClockSkewSeconds == nil {
		t.Fatalf("clockSkewSeconds = nil, want %.3f populated by probe stub", planted)
	}
	if *got.ClockSkewSeconds != planted {
		t.Fatalf("clockSkewSeconds = %v, want %v (3-decimal-rounded planted value)", *got.ClockSkewSeconds, planted)
	}
	foundSkewWarning := false
	for _, w := range got.Warnings {
		if len(w) >= len("clock skew") && w[:len("clock skew")] == "clock skew" {
			foundSkewWarning = true
			break
		}
	}
	if !foundSkewWarning {
		t.Fatalf("expected a clock-skew warning given planted %.1fs > %v threshold, got: %v",
			planted, ClockSkewWarnThresholdSeconds, got.Warnings)
	}
}

// TestSystemTimeHealth_NoProbe_OmitsField: the default constructor must
// leave `clockSkewSeconds` nil so the JSON `omitempty` drops the key
// entirely. This pins the "cheap by default" contract — flipping the
// probe back off in YAML must produce a payload identical (modulo
// timestamps) to firmware predating iter 28.
func TestSystemTimeHealth_NoProbe_OmitsField(t *testing.T) {
	h := NewSystemTimeHealthHandler()
	r := newTimeHealthRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/system/time-health", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := raw["clockSkewSeconds"]; present {
		t.Fatalf("clockSkewSeconds must be omitted when probe is disabled, body=%s", rr.Body.String())
	}
}

// TestSystemTimeHealth_WarnsOnUTCFallback: when readCurrentTimezone returns
// the UTC fallback (the dev/test default — no TZ env, no timedatectl, no
// /etc/localtime symlink), the handler MUST surface a warning so the
// dashboard nudges the operator to set a real zone.
func TestSystemTimeHealth_WarnsOnUTCFallback(t *testing.T) {
	t.Setenv("TZ", "")
	h := NewSystemTimeHealthHandler()
	r := newTimeHealthRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/system/time-health", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	var got systemTimeHealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// In simulated mode with no TZ env we expect either Source=="fallback"
	// + IsUTC=true, OR (on a Linux dev host with /etc/localtime set to a
	// non-UTC zone) Source=="etc_localtime" + IsUTC=false. Both are
	// acceptable; only the first must produce a warning.
	if got.TimezoneSource == "fallback" {
		if !got.IsUTC {
			t.Fatalf("source=fallback but IsUTC=false — fallback always returns UTC")
		}
		foundWarning := false
		for _, w := range got.Warnings {
			if len(w) > 0 && (w[0] == 't') {
				foundWarning = true
				break
			}
		}
		if !foundWarning {
			t.Fatalf("expected a warning when source=fallback, got %d warnings", len(got.Warnings))
		}
	}
}
