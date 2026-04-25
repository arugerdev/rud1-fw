package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/audit/configlog"
)

// newAuditRouter mounts only the /api/system/audit handler around the
// given logger so the tests stay self-contained.
func newAuditRouter(t *testing.T, l configlog.Logger) *chi.Mux {
	t.Helper()
	h := NewSystemAuditHandler(l)
	r := chi.NewRouter()
	r.Get("/api/system/audit", h.List)
	return r
}

// seedDiskLogger writes n entries into a fresh DiskLogger rooted at
// t.TempDir(). Entries are stamped one second apart starting at base
// so the newest-first ordering is unambiguous.
func seedDiskLogger(t *testing.T, n int, base time.Time, action string) configlog.Logger {
	t.Helper()
	dir := t.TempDir()
	now := base
	l, err := configlog.New(dir, configlog.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("configlog.New: %v", err)
	}
	for i := 0; i < n; i++ {
		now = base.Add(time.Duration(i) * time.Second)
		e := configlog.Entry{
			At:     now.Unix(),
			Action: action,
			Actor:  "operator",
			OK:     true,
			Next:   map[string]any{"i": i},
		}
		if err := l.Append(context.Background(), e); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// TestSystemAudit_NoopReturnsEmptyOK: with the no-op logger the handler
// still serves a 200 + empty list so the UI can render unconditionally.
func TestSystemAudit_NoopReturnsEmptyOK(t *testing.T) {
	r := newAuditRouter(t, configlog.LoggerNoop{})

	req := httptest.NewRequest(http.MethodGet, "/api/system/audit", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got auditListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Entries) != 0 {
		t.Fatalf("entries=%d, want 0", len(got.Entries))
	}
	if got.Total != 0 {
		t.Fatalf("total=%d, want 0", got.Total)
	}
}

// TestSystemAudit_NilLoggerNotPanics: the constructor must coerce a nil
// logger into LoggerNoop so callers can pass `nil` defensively.
func TestSystemAudit_NilLoggerNotPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	h := NewSystemAuditHandler(nil)
	if h == nil {
		t.Fatalf("constructor returned nil")
	}
}

// TestSystemAudit_PaginationNewestFirst seeds 5 entries and asserts the
// response is newest-first and respects limit + offset.
func TestSystemAudit_PaginationNewestFirst(t *testing.T) {
	base := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	l := seedDiskLogger(t, 5, base, "system.timezone.set")
	r := newAuditRouter(t, l)

	req := httptest.NewRequest(http.MethodGet, "/api/system/audit?limit=3&offset=1", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got auditListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Total != 5 {
		t.Fatalf("total=%d, want 5", got.Total)
	}
	if len(got.Entries) != 3 {
		t.Fatalf("entries=%d, want 3", len(got.Entries))
	}
	// Newest is i=4 at offset=0; with offset=1 we expect i=3,2,1.
	wantIdx := []float64{3, 2, 1}
	for j, want := range wantIdx {
		got := got.Entries[j].Next.(map[string]any)["i"].(float64)
		if got != want {
			t.Fatalf("entry[%d].Next.i=%v, want %v", j, got, want)
		}
	}
}

// TestSystemAudit_FilterByAction: only entries whose action equals the
// query string are returned, and total is also filtered.
func TestSystemAudit_FilterByAction(t *testing.T) {
	base := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	now := base
	l, err := configlog.New(dir, configlog.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("configlog.New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	// 3 timezone, 2 ntpProbe.
	mk := func(i int, action string) {
		now = base.Add(time.Duration(i) * time.Second)
		if err := l.Append(context.Background(), configlog.Entry{
			At: now.Unix(), Action: action, Actor: "operator", OK: true,
		}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	mk(0, "system.timezone.set")
	mk(1, "system.ntpProbe.update")
	mk(2, "system.timezone.set")
	mk(3, "system.ntpProbe.update")
	mk(4, "system.timezone.set")

	r := newAuditRouter(t, l)
	req := httptest.NewRequest(http.MethodGet, "/api/system/audit?action=system.ntpProbe.update", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got auditListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Total != 2 {
		t.Fatalf("total=%d, want 2", got.Total)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("entries=%d, want 2", len(got.Entries))
	}
	for _, e := range got.Entries {
		if e.Action != "system.ntpProbe.update" {
			t.Fatalf("action=%q leaked through filter", e.Action)
		}
	}
}

// TestSystemAudit_FilterBySinceUntil: window query trims results on
// both sides; total mirrors the window.
func TestSystemAudit_FilterBySinceUntil(t *testing.T) {
	base := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	l := seedDiskLogger(t, 5, base, "system.timezone.set")
	r := newAuditRouter(t, l)

	since := base.Add(1 * time.Second).Unix()
	until := base.Add(3 * time.Second).Unix()
	url := fmt.Sprintf("/api/system/audit?since=%d&until=%d", since, until)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got auditListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Total != 3 {
		t.Fatalf("total=%d, want 3 (window covers i=1,2,3)", got.Total)
	}
}

// TestSystemAudit_RejectsInvalidQuery: every numeric field rejects
// negatives and non-numeric values; limit also rejects oversized.
func TestSystemAudit_RejectsInvalidQuery(t *testing.T) {
	r := newAuditRouter(t, configlog.LoggerNoop{})
	cases := []string{
		"limit=-1",
		"limit=abc",
		"limit=9999",
		"offset=-1",
		"offset=xx",
		"since=-5",
		"until=-7",
		"since=zz",
	}
	for _, q := range cases {
		t.Run(q, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/system/audit?"+q, nil)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d, want 400; body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

// TestSystemAudit_DefaultLimitAppliedWhenMissing: omitting limit
// returns up to auditDefaultLimit entries even if more exist.
func TestSystemAudit_DefaultLimitAppliedWhenMissing(t *testing.T) {
	base := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	// Seed more than auditDefaultLimit so we can prove the cap.
	l := seedDiskLogger(t, auditDefaultLimit+5, base, "system.timezone.set")
	r := newAuditRouter(t, l)

	req := httptest.NewRequest(http.MethodGet, "/api/system/audit", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got auditListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Total != auditDefaultLimit+5 {
		t.Fatalf("total=%d, want %d", got.Total, auditDefaultLimit+5)
	}
	if len(got.Entries) != auditDefaultLimit {
		t.Fatalf("entries=%d, want %d", len(got.Entries), auditDefaultLimit)
	}
}
