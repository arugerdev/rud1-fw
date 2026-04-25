package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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
	if _, err := l.PruneOld(); err != nil {
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

// fakePruner is a test double for the retentionPruner contract used by
// the Set handler. It records every SetMaxFiles + PruneOld invocation
// (with their arguments) so tests can assert call counts, ordering,
// and the exact retention bound passed in. Optionally returns a fixed
// error from PruneOld to exercise the prune-fails-but-persist-wins
// branch. Safe for concurrent use.
type fakePruner struct {
	mu             sync.Mutex
	setMaxCalls    []int
	pruneCalls     atomic.Int32
	prunedPerCall  int
	pruneErr       error
	currentMaxFile int
}

func (f *fakePruner) SetMaxFiles(n int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	prev := f.currentMaxFile
	f.currentMaxFile = n
	f.setMaxCalls = append(f.setMaxCalls, n)
	return prev
}

func (f *fakePruner) PruneOld() (int, error) {
	f.pruneCalls.Add(1)
	return f.prunedPerCall, f.pruneErr
}

func (f *fakePruner) lastSetMax() (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.setMaxCalls) == 0 {
		return 0, false
	}
	return f.setMaxCalls[len(f.setMaxCalls)-1], true
}

// retentionTestEnv wraps the on-disk pieces a Set test needs: a config
// loaded from a writable temp YAML so cfg.Save() round-trips, plus a
// stubbable pruner the test can interrogate.
type retentionTestEnv struct {
	cfg    *config.Config
	pruner *fakePruner
	h      *SystemAuditRetentionHandler
	router *chi.Mux
}

func newRetentionSetEnv(t *testing.T, initialDays int) *retentionTestEnv {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf(`
server:
  host: "127.0.0.1"
  port: 8080
  auth_token: "t"
system:
  audit_retention_days: %d
`, initialDays)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	pruner := &fakePruner{currentMaxFile: cfg.System.AuditRetentionDaysOrDefault()}
	h := NewSystemAuditRetentionHandler(cfg, nil)
	h.setPrunerForTest(pruner)
	r := chi.NewRouter()
	r.Get("/api/system/audit/retention", h.Get)
	r.Put("/api/system/audit/retention", h.Set)
	return &retentionTestEnv{cfg: cfg, pruner: pruner, h: h, router: r}
}

func putRetention(t *testing.T, r *chi.Mux, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/system/audit/retention", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

// TestSystemAuditRetention_Set_Shrink_TriggersImmediatePrune covers the
// happy path: 14 → 3 must persist, reconfigure the live retention
// bound, AND fire one PruneOld so out-of-window day-files vanish.
func TestSystemAuditRetention_Set_Shrink_TriggersImmediatePrune(t *testing.T) {
	env := newRetentionSetEnv(t, 14)
	env.pruner.prunedPerCall = 11

	rr := putRetention(t, env.router, `{"days":3}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if got := env.cfg.System.AuditRetentionDays; got != 3 {
		t.Fatalf("persisted days=%d, want 3", got)
	}
	if env.pruner.pruneCalls.Load() != 1 {
		t.Fatalf("PruneOld calls=%d, want 1", env.pruner.pruneCalls.Load())
	}
	last, ok := env.pruner.lastSetMax()
	if !ok || last != 3 {
		t.Fatalf("SetMaxFiles last=%d ok=%v, want 3 true", last, ok)
	}
}

// TestSystemAuditRetention_Set_Grow_NoPrune covers 3 → 14: nothing on
// disk falls outside the new (wider) window, so PruneOld must NOT run.
// SetMaxFiles still runs so future appends honour the new bound — but
// the iter-39 contract is specifically about prune-on-shrink.
func TestSystemAuditRetention_Set_Grow_NoPrune(t *testing.T) {
	env := newRetentionSetEnv(t, 3)

	rr := putRetention(t, env.router, `{"days":14}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if got := env.cfg.System.AuditRetentionDays; got != 14 {
		t.Fatalf("persisted days=%d, want 14", got)
	}
	if env.pruner.pruneCalls.Load() != 0 {
		t.Fatalf("PruneOld calls=%d, want 0 on grow", env.pruner.pruneCalls.Load())
	}
}

// TestSystemAuditRetention_Set_Unchanged_NoPrune covers the
// no-op-mutation path: same value in, same value out, no prune.
func TestSystemAuditRetention_Set_Unchanged_NoPrune(t *testing.T) {
	env := newRetentionSetEnv(t, 7)

	rr := putRetention(t, env.router, `{"days":7}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if env.pruner.pruneCalls.Load() != 0 {
		t.Fatalf("PruneOld calls=%d, want 0 on unchanged", env.pruner.pruneCalls.Load())
	}
}

// TestSystemAuditRetention_Set_PruneError_Returns200 mirrors the
// timezone handler's "audit append failure never propagates" pattern:
// when the persistence wins but the prune sweep fails, the operator
// still gets a 200 (their config did land) and the agent logs the
// prune error. A 500 would falsely tell the cloud "retention change
// rejected" when in fact it succeeded.
func TestSystemAuditRetention_Set_PruneError_Returns200(t *testing.T) {
	env := newRetentionSetEnv(t, 14)
	env.pruner.pruneErr = errors.New("forced prune failure")

	rr := putRetention(t, env.router, `{"days":3}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 (prune failure must not propagate); body=%s", rr.Code, rr.Body.String())
	}
	if got := env.cfg.System.AuditRetentionDays; got != 3 {
		t.Fatalf("persisted days=%d, want 3 (persist must win even when prune errors)", got)
	}
	if env.pruner.pruneCalls.Load() != 1 {
		t.Fatalf("PruneOld calls=%d, want 1", env.pruner.pruneCalls.Load())
	}
}

// TestSystemAuditRetention_Set_RejectsOutOfRange covers the validator:
// values below MinAuditRetentionDays or above MaxAuditRetentionDays
// must yield 400 + a stable error message AND must not mutate the
// persisted retention or trigger a prune.
func TestSystemAuditRetention_Set_RejectsOutOfRange(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"zero rejected", `{"days":0}`},
		{"negative rejected", `{"days":-1}`},
		{"over max rejected", fmt.Sprintf(`{"days":%d}`, config.MaxAuditRetentionDays+1)},
		{"missing field rejected", `{}`},
		{"unknown field rejected", `{"days":3,"extra":"x"}`},
		{"invalid json rejected", `not-json`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newRetentionSetEnv(t, 14)
			rr := putRetention(t, env.router, tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d, want 400; body=%s", rr.Code, rr.Body.String())
			}
			if got := env.cfg.System.AuditRetentionDays; got != 14 {
				t.Fatalf("persisted days=%d, want 14 (must not mutate on bad request)", got)
			}
			if env.pruner.pruneCalls.Load() != 0 {
				t.Fatalf("PruneOld calls=%d, want 0 on bad request", env.pruner.pruneCalls.Load())
			}
		})
	}
}

// TestSystemAuditRetention_Set_ConcurrentNoDoublePrune fires two
// concurrent shrink PUTs and asserts the handler's mutex serialises
// them so the prune count matches the number of successful shrinks
// (one per call). Without the mutex two concurrent shrinks could
// race the SetMaxFiles → PruneOld pair and either skip a prune or
// double-fire one against an inconsistent maxFiles snapshot.
func TestSystemAuditRetention_Set_ConcurrentNoDoublePrune(t *testing.T) {
	env := newRetentionSetEnv(t, 14)

	const N = 8
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			// Mix of shrinks; same target value so the second-onwards
			// PUTs are unchanged-no-ops and must NOT prune.
			rr := putRetention(t, env.router, `{"days":3}`)
			if rr.Code != http.StatusOK {
				t.Errorf("[%d] status=%d, want 200; body=%s", i, rr.Code, rr.Body.String())
			}
		}(i)
	}
	wg.Wait()

	// Exactly ONE shrink (14→3) must have triggered a prune; the rest
	// see a no-change (3→3) and skip the prune entirely. Anything else
	// means the mutex didn't serialise the persist-then-prune block.
	if got := env.pruner.pruneCalls.Load(); got != 1 {
		t.Fatalf("PruneOld total calls=%d, want exactly 1 across %d concurrent PUTs", got, N)
	}
	if got := env.cfg.System.AuditRetentionDays; got != 3 {
		t.Fatalf("persisted days=%d, want 3", got)
	}
}

// TestSystemAuditRetention_Set_RejectsBadMethod ensures a stray POST
// to the same path falls through to chi's MethodNotAllowed instead of
// silently invoking Set. Belt-and-braces against future router
// refactors that might broaden the route's method match.
func TestSystemAuditRetention_Set_RejectsBadMethod(t *testing.T) {
	env := newRetentionSetEnv(t, 14)
	req := httptest.NewRequest(http.MethodPost, "/api/system/audit/retention", bytes.NewBufferString(`{"days":3}`))
	rr := httptest.NewRecorder()
	env.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", rr.Code)
	}
	if env.pruner.pruneCalls.Load() != 0 {
		t.Fatalf("PruneOld calls=%d, want 0 on bad method", env.pruner.pruneCalls.Load())
	}
}

// TestSystemAuditRetention_Set_NilPrunerSkipsCleanly: when the disk
// logger is unavailable (read-only fs at boot) the handler keeps the
// persistence path honest and just skips the prune step — no panic,
// still a 200. Mirrors the Get handler's nil-logger tolerance.
func TestSystemAuditRetention_Set_NilPrunerSkipsCleanly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `
server:
  host: "127.0.0.1"
  port: 8080
  auth_token: "t"
system:
  audit_retention_days: 14
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	h := NewSystemAuditRetentionHandler(cfg, nil)
	r := chi.NewRouter()
	r.Put("/api/system/audit/retention", h.Set)

	rr := putRetention(t, r, `{"days":3}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if got := cfg.System.AuditRetentionDays; got != 3 {
		t.Fatalf("persisted days=%d, want 3", got)
	}
}
