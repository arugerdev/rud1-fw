package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
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
