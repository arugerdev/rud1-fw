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

	"github.com/rud1-es/rud1-fw/internal/config"
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

// auditRetentionWire mirrors auditRetentionResponse for tests; using a
// local copy keeps the production type strictly internal.
type auditRetentionWire struct {
	ConfiguredDays int        `json:"configuredDays"`
	EffectiveDays  int        `json:"effectiveDays"`
	Default        int        `json:"default"`
	MinDays        int        `json:"minDays"`
	MaxDays        int        `json:"maxDays"`
	TotalEntries   int        `json:"totalEntries"`
	TotalBytes     int64      `json:"totalBytes"`
	FileCount      int        `json:"fileCount"`
	OldestEntryAt  *time.Time `json:"oldestEntryAt,omitempty"`
	NewestEntryAt  *time.Time `json:"newestEntryAt,omitempty"`
	LastPruneAt    *time.Time `json:"lastPruneAt,omitempty"`
}

// newRetentionRouter mounts the retention handler around the supplied
// cfg + DiskLogger so each test asserts its own scenario in isolation.
func newRetentionRouter(t *testing.T, cfg *config.Config, l *configlog.DiskLogger) *chi.Mux {
	t.Helper()
	h := NewSystemAuditRetentionHandler(cfg, l)
	r := chi.NewRouter()
	r.Get("/api/system/audit/retention", h.Get)
	return r
}

// TestSystemAuditRetention_NilLoggerReturnsConfigOnly: when the disk
// logger is nil (e.g. read-only fs at boot), the handler still serves
// the configured/effective retention numbers and zero stats.
func TestSystemAuditRetention_NilLoggerReturnsConfigOnly(t *testing.T) {
	cfg := config.Default()
	r := newRetentionRouter(t, cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/system/audit/retention", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type=%q, want application/json", ct)
	}
	var got auditRetentionWire
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Default != config.DefaultAuditRetentionDays {
		t.Fatalf("default=%d, want %d", got.Default, config.DefaultAuditRetentionDays)
	}
	if got.MinDays != config.MinAuditRetentionDays {
		t.Fatalf("minDays=%d, want %d", got.MinDays, config.MinAuditRetentionDays)
	}
	if got.MaxDays != config.MaxAuditRetentionDays {
		t.Fatalf("maxDays=%d, want %d", got.MaxDays, config.MaxAuditRetentionDays)
	}
	if got.TotalEntries != 0 || got.TotalBytes != 0 || got.FileCount != 0 {
		t.Fatalf("expected zero stats, got %+v", got)
	}
	if got.OldestEntryAt != nil || got.NewestEntryAt != nil || got.LastPruneAt != nil {
		t.Fatalf("expected nil time fields, got %+v", got)
	}
}

// TestSystemAuditRetention_EmptyDir: a fresh DiskLogger with no entries
// reports zero counts and no oldest/newest, but lastPruneAt is set
// (New() runs an opportunistic prune).
func TestSystemAuditRetention_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	fixed := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	l, err := configlog.New(dir, configlog.Options{Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatalf("configlog.New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	cfg := config.Default()
	r := newRetentionRouter(t, cfg, l)

	req := httptest.NewRequest(http.MethodGet, "/api/system/audit/retention", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	var got auditRetentionWire
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.TotalEntries != 0 || got.FileCount != 0 || got.TotalBytes != 0 {
		t.Fatalf("expected zero stats: %+v", got)
	}
	if got.OldestEntryAt != nil || got.NewestEntryAt != nil {
		t.Fatalf("expected nil oldest/newest, got %+v / %+v", got.OldestEntryAt, got.NewestEntryAt)
	}
	if got.LastPruneAt == nil {
		t.Fatalf("LastPruneAt should be set after New(): got nil")
	}
}

// TestSystemAuditRetention_PopulatedDir: counts + bytes accumulate and
// oldest/newest reflect entry timestamps.
func TestSystemAuditRetention_PopulatedDir(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	now := base
	l, err := configlog.New(dir, configlog.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("configlog.New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	for i := 0; i < 4; i++ {
		now = base.Add(time.Duration(i) * time.Second)
		if err := l.Append(context.Background(), configlog.Entry{
			At: now.Unix(), Action: "system.timezone.set", Actor: "operator", OK: true,
		}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	cfg := config.Default()
	r := newRetentionRouter(t, cfg, l)
	req := httptest.NewRequest(http.MethodGet, "/api/system/audit/retention", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got auditRetentionWire
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.TotalEntries != 4 {
		t.Fatalf("TotalEntries=%d, want 4", got.TotalEntries)
	}
	if got.FileCount != 1 {
		t.Fatalf("FileCount=%d, want 1", got.FileCount)
	}
	if got.TotalBytes <= 0 {
		t.Fatalf("TotalBytes=%d, want >0", got.TotalBytes)
	}
	if got.OldestEntryAt == nil || got.OldestEntryAt.Unix() != base.Unix() {
		t.Fatalf("OldestEntryAt=%v, want %v", got.OldestEntryAt, base)
	}
	wantNewest := base.Add(3 * time.Second)
	if got.NewestEntryAt == nil || got.NewestEntryAt.Unix() != wantNewest.Unix() {
		t.Fatalf("NewestEntryAt=%v, want %v", got.NewestEntryAt, wantNewest)
	}
}

// TestSystemAuditRetention_ConfiguredAndEffective: a raw configured
// value of 0 must surface as configuredDays=0 with effectiveDays
// falling back to the default; oversized configured values clamp to
// the max for effectiveDays while configured stays raw.
func TestSystemAuditRetention_ConfiguredAndEffective(t *testing.T) {
	cases := []struct {
		name           string
		configured     int
		wantEffective  int
		wantConfigured int
	}{
		{"zero falls back to default", 0, config.DefaultAuditRetentionDays, 0},
		{"explicit value passes through", 30, 30, 30},
		{"oversized clamps to max", 9999, config.MaxAuditRetentionDays, 9999},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.System.AuditRetentionDays = tc.configured
			r := newRetentionRouter(t, cfg, nil)

			req := httptest.NewRequest(http.MethodGet, "/api/system/audit/retention", nil)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d, want 200", rr.Code)
			}
			var got auditRetentionWire
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.ConfiguredDays != tc.wantConfigured {
				t.Fatalf("configuredDays=%d, want %d", got.ConfiguredDays, tc.wantConfigured)
			}
			if got.EffectiveDays != tc.wantEffective {
				t.Fatalf("effectiveDays=%d, want %d", got.EffectiveDays, tc.wantEffective)
			}
		})
	}
}

// TestSystemAuditRetention_LastPruneAtAfterManualPrune: calling
// PruneOld() at a known clock value advances lastPruneAt visible
// through the handler.
func TestSystemAuditRetention_LastPruneAtAfterManualPrune(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 4, 25, 0, 0, 1, 0, time.UTC)
	now := t0
	l, err := configlog.New(dir, configlog.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("configlog.New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	t1 := t0.Add(3 * time.Hour)
	now = t1
	if err := l.PruneOld(); err != nil {
		t.Fatalf("PruneOld: %v", err)
	}

	cfg := config.Default()
	r := newRetentionRouter(t, cfg, l)
	req := httptest.NewRequest(http.MethodGet, "/api/system/audit/retention", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	var got auditRetentionWire
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.LastPruneAt == nil {
		t.Fatalf("LastPruneAt is nil after PruneOld()")
	}
	if !got.LastPruneAt.Equal(t1) {
		t.Fatalf("LastPruneAt=%v, want %v", got.LastPruneAt, t1)
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
