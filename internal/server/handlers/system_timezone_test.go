package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func newTimezoneRouter(h *SystemTimezoneHandler) *chi.Mux {
	r := chi.NewRouter()
	r.Get("/api/system/timezone", h.Get)
	r.Post("/api/system/timezone", h.Set)
	return r
}

// TestSystemTimezone_Get_ReturnsCurrentAndSuggestions: the GET handler
// always responds 200 with a non-empty current zone (UTC fallback) and a
// suggested list — even on simulated hardware where /usr/share/zoneinfo
// may not exist.
func TestSystemTimezone_Get_ReturnsCurrentAndSuggestions(t *testing.T) {
	h := NewSystemTimezoneHandler()
	r := newTimezoneRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/system/timezone", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	var got systemTimezoneResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Current == "" {
		t.Fatalf("current = empty, want non-empty zone (UTC fallback at minimum)")
	}
	if len(got.Suggested) == 0 {
		t.Fatalf("suggested = empty, want at least the curated fallback list")
	}
	// The curated list must always include UTC + Europe/Madrid as
	// operator-friendly defaults.
	wantContains := []string{"UTC", "Europe/Madrid"}
	for _, want := range wantContains {
		found := false
		for _, tz := range got.Suggested {
			if tz == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("suggested missing %q — got %d entries", want, len(got.Suggested))
		}
	}
}

// TestSystemTimezone_Set_RejectsUnknown: an obviously bogus zone is rejected
// with 400 before any timedatectl invocation.
func TestSystemTimezone_Set_RejectsUnknown(t *testing.T) {
	h := NewSystemTimezoneHandler()
	r := newTimezoneRouter(h)

	body := strings.NewReader(`{"timezone":"Mars/Olympus_Mons"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/system/timezone", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unknown timezone") {
		t.Fatalf("body = %q, want 'unknown timezone' error", rr.Body.String())
	}
}

// TestSystemTimezone_Set_RejectsEmpty: empty/whitespace payloads must 400.
func TestSystemTimezone_Set_RejectsEmpty(t *testing.T) {
	h := NewSystemTimezoneHandler()
	r := newTimezoneRouter(h)

	body := strings.NewReader(`{"timezone":""}`)
	req := httptest.NewRequest(http.MethodPost, "/api/system/timezone", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — body=%s", rr.Code, rr.Body.String())
	}
}

// TestSystemTimezone_Set_RejectsPathEscape: zones containing path-traversal
// hints must be rejected even before tzdata lookup.
func TestSystemTimezone_Set_RejectsPathEscape(t *testing.T) {
	for _, tz := range []string{"../etc/passwd", "/Europe/Madrid", "Europe/../Madrid"} {
		body := strings.NewReader(`{"timezone":"` + tz + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/system/timezone", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		newTimezoneRouter(NewSystemTimezoneHandler()).ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("tz=%q: status = %d, want 400", tz, rr.Code)
		}
	}
}

// TestSystemTimezone_Set_AcceptsCuratedZone: a zone from the fallback
// curated list must be accepted on simulated hardware (no timedatectl
// invocation). Asserts the handler returns 200 + echoes back current.
func TestSystemTimezone_Set_AcceptsCuratedZone(t *testing.T) {
	h := NewSystemTimezoneHandler()
	r := newTimezoneRouter(h)

	body := strings.NewReader(`{"timezone":"Europe/Madrid"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/system/timezone", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	var got systemTimezoneResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Current == "" {
		t.Fatalf("current = empty after Set")
	}
}

// TestSystemTimezone_Set_RejectsInvalidJSON: malformed JSON must 400 with a
// stable error shape.
func TestSystemTimezone_Set_RejectsInvalidJSON(t *testing.T) {
	h := NewSystemTimezoneHandler()
	r := newTimezoneRouter(h)

	body := strings.NewReader(`{"timezone":`)
	req := httptest.NewRequest(http.MethodPost, "/api/system/timezone", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid JSON") {
		t.Fatalf("body = %q, want 'invalid JSON' error", rr.Body.String())
	}
}

// TestTimezoneFromLocaltimePath: covers the small parser used by the
// fallback path-derivation when timedatectl isn't available.
func TestTimezoneFromLocaltimePath(t *testing.T) {
	cases := map[string]string{
		"/usr/share/zoneinfo/Europe/Madrid":    "Europe/Madrid",
		"../usr/share/zoneinfo/America/Bogota": "America/Bogota",
		"/usr/share/zoneinfo/UTC":              "UTC",
		"/etc/localtime":                       "",
		"":                                     "",
		"/usr/share/zoneinfo/../etc/passwd":    "",
	}
	for in, want := range cases {
		got := timezoneFromLocaltimePath(in)
		if got != want {
			t.Errorf("timezoneFromLocaltimePath(%q) = %q, want %q", in, got, want)
		}
	}
}
