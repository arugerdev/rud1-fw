package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

// fakeDesiredConfigSource stubs the iter-52 applier surface for handler
// tests. Both fields default to their zero value so a fresh-device
// scenario is the implicit default — explicit cases populate them.
type fakeDesiredConfigSource struct {
	at     *time.Time
	fields []string
}

func (f fakeDesiredConfigSource) LastAppliedAt() *time.Time {
	if f.at == nil {
		return nil
	}
	t := *f.at
	return &t
}

func (f fakeDesiredConfigSource) LastAppliedFields() []string {
	if f.fields == nil {
		return nil
	}
	out := make([]string, len(f.fields))
	copy(out, f.fields)
	return out
}

// newDesiredConfigRouter mounts the iter-52 handler around the given
// stub source, mirroring the local-router shape the real server.New
// wires up. Lets each test stay self-contained.
func newDesiredConfigRouter(src DesiredConfigLastAppliedSource) *chi.Mux {
	h := NewSystemDesiredConfigHandler(src)
	r := chi.NewRouter()
	r.Get("/api/system/desired-config/last-applied", h.LastApplied)
	return r
}

// decodeDesiredConfigBody is the test helper that asserts the JSON
// shape (lastAppliedAt + fields) without leaking decoder boilerplate
// into every test body.
func decodeDesiredConfigBody(t *testing.T, body []byte) (lastApplied *time.Time, fields []string) {
	t.Helper()
	var out struct {
		LastAppliedAt *time.Time `json:"lastAppliedAt"`
		Fields        []string   `json:"fields"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, string(body))
	}
	return out.LastAppliedAt, out.Fields
}

// TestSystemDesiredConfig_NeverApplied: a freshly-booted device with no
// cloud apply on record must serve a 200 with `lastAppliedAt: null` and
// an empty (NEVER null) `fields` array. The local panel does a
// length-check on `fields`, not a nil-guard, so a null array is a UI
// regression.
func TestSystemDesiredConfig_NeverApplied(t *testing.T) {
	r := newDesiredConfigRouter(fakeDesiredConfigSource{})
	req := httptest.NewRequest(http.MethodGet, "/api/system/desired-config/last-applied", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	at, fields := decodeDesiredConfigBody(t, rr.Body.Bytes())
	if at != nil {
		t.Fatalf("lastAppliedAt=%v, want null", at)
	}
	if fields == nil {
		t.Fatalf("fields=null, want []")
	}
	if len(fields) != 0 {
		t.Fatalf("fields=%v, want []", fields)
	}
}

// TestSystemDesiredConfig_AppliedOnceSingleField: the happy path —
// applier reports a non-nil timestamp + a one-element field slice; the
// handler echoes both.
func TestSystemDesiredConfig_AppliedOnceSingleField(t *testing.T) {
	pinned := time.Date(2026, 4, 26, 12, 30, 0, 0, time.UTC)
	r := newDesiredConfigRouter(fakeDesiredConfigSource{
		at:     &pinned,
		fields: []string{"auditRetentionDays"},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/system/desired-config/last-applied", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	at, fields := decodeDesiredConfigBody(t, rr.Body.Bytes())
	if at == nil || !at.Equal(pinned) {
		t.Fatalf("lastAppliedAt=%v, want %v", at, pinned)
	}
	if len(fields) != 1 || fields[0] != "auditRetentionDays" {
		t.Fatalf("fields=%v, want [auditRetentionDays]", fields)
	}
}

// TestSystemDesiredConfig_NormalisesToUTC: the applier stores
// time.Now() in the device's local zone; the handler MUST normalise to
// UTC so the JSON wire shape carries a `Z` suffix that the local
// panel's parser can rely on.
func TestSystemDesiredConfig_NormalisesToUTC(t *testing.T) {
	cest := time.FixedZone("CEST", 2*3600)
	local := time.Date(2026, 4, 26, 14, 30, 0, 0, cest)
	r := newDesiredConfigRouter(fakeDesiredConfigSource{
		at:     &local,
		fields: []string{"externalNTPServers"},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/system/desired-config/last-applied", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	at, _ := decodeDesiredConfigBody(t, rr.Body.Bytes())
	if at == nil {
		t.Fatalf("lastAppliedAt=nil")
	}
	if at.Location() != time.UTC {
		t.Fatalf("location=%v, want UTC", at.Location())
	}
	if !at.Equal(local) {
		t.Fatalf("UTC normalisation lost wall-clock equivalence: %v vs %v", at, local)
	}
}

// TestSystemDesiredConfig_MultiField: every field name from the
// canonical iter-50/51 set echoes through. Pin the names verbatim so a
// rename in the applier breaks both sides at once instead of silently
// shipping a stale string to the local panel.
func TestSystemDesiredConfig_MultiField(t *testing.T) {
	pinned := time.Date(2026, 4, 26, 13, 0, 0, 0, time.UTC)
	want := []string{"auditRetentionDays", "externalNTPProbeEnabled", "externalNTPServers", "lanRoutes"}
	r := newDesiredConfigRouter(fakeDesiredConfigSource{at: &pinned, fields: want})
	req := httptest.NewRequest(http.MethodGet, "/api/system/desired-config/last-applied", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	_, fields := decodeDesiredConfigBody(t, rr.Body.Bytes())
	if len(fields) != len(want) {
		t.Fatalf("fields=%v, want %v", fields, want)
	}
	for i, f := range want {
		if fields[i] != f {
			t.Fatalf("fields[%d]=%q, want %q", i, fields[i], f)
		}
	}
}

// TestSystemDesiredConfig_NilSource: dev-hardware path where the agent
// didn't construct the applier at all (e.g. a unit-test agent stub).
// The handler MUST still serve a 200 with the empty/null payload —
// not a 503 — so the local panel renders unconditionally.
func TestSystemDesiredConfig_NilSource(t *testing.T) {
	r := newDesiredConfigRouter(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/system/desired-config/last-applied", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	at, fields := decodeDesiredConfigBody(t, rr.Body.Bytes())
	if at != nil {
		t.Fatalf("lastAppliedAt=%v, want null", at)
	}
	if fields == nil || len(fields) != 0 {
		t.Fatalf("fields=%v, want []", fields)
	}
}
