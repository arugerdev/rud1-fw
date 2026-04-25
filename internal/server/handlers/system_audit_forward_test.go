package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/audit/configlog"
)

// fakeAuditCursorSource is a trivial AuditCursorSource for tests.
type fakeAuditCursorSource struct{ at time.Time }

func (f fakeAuditCursorSource) AuditCursor() time.Time { return f.at }

// newAuditForwardRouter mounts the forward-status handler around the
// given dependencies so tests stay self-contained.
func newAuditForwardRouter(src AuditCursorSource, l configlog.Logger, cloudEnabled bool) *chi.Mux {
	h := NewSystemAuditForwardStatusHandler(src, l, cloudEnabled)
	r := chi.NewRouter()
	r.Get("/api/system/audit/forward-status", h.Status)
	return r
}

func decodeForwardStatus(t *testing.T, body []byte) auditForwardStatusResponse {
	t.Helper()
	var out auditForwardStatusResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, string(body))
	}
	return out
}

// TestAuditForwardStatus_NoopLoggerReportsUnavailable: when the disk
// logger failed to open and we fell back to LoggerNoop, the response
// must report auditAvailable=false so the UI shows the "local audit
// unavailable" hint instead of a misleading "0 pending".
func TestAuditForwardStatus_NoopLoggerReportsUnavailable(t *testing.T) {
	r := newAuditForwardRouter(fakeAuditCursorSource{}, configlog.LoggerNoop{}, true)
	req := httptest.NewRequest(http.MethodGet, "/api/system/audit/forward-status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	got := decodeForwardStatus(t, rr.Body.Bytes())
	if got.AuditAvailable {
		t.Fatalf("auditAvailable=true, want false")
	}
	if !got.CloudEnabled {
		t.Fatalf("cloudEnabled=false, want true")
	}
	if got.PendingCount != 0 {
		t.Fatalf("pendingCount=%d, want 0", got.PendingCount)
	}
	if got.CursorAt != nil {
		t.Fatalf("cursorAt=%v, want nil", got.CursorAt)
	}
}

// TestAuditForwardStatus_CloudDisabled: even with a real audit logger,
// when cloud is disabled the response must reflect it so the UI can
// suppress the "pending forward" warning (entries will never ship).
func TestAuditForwardStatus_CloudDisabled(t *testing.T) {
	base := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	l := seedDiskLogger(t, 3, base, "test.action")
	r := newAuditForwardRouter(fakeAuditCursorSource{}, l, false)
	req := httptest.NewRequest(http.MethodGet, "/api/system/audit/forward-status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	got := decodeForwardStatus(t, rr.Body.Bytes())
	if got.CloudEnabled {
		t.Fatalf("cloudEnabled=true, want false")
	}
	if !got.AuditAvailable {
		t.Fatalf("auditAvailable=false, want true")
	}
}

// TestAuditForwardStatus_NoCursor_AllPending: when the cursor is the
// zero time (first boot of an upgraded agent), every on-disk entry
// counts as pending.
func TestAuditForwardStatus_NoCursor_AllPending(t *testing.T) {
	base := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	l := seedDiskLogger(t, 5, base, "test.action")
	r := newAuditForwardRouter(fakeAuditCursorSource{at: time.Time{}}, l, true)
	req := httptest.NewRequest(http.MethodGet, "/api/system/audit/forward-status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	got := decodeForwardStatus(t, rr.Body.Bytes())
	if got.PendingCount != 5 {
		t.Fatalf("pendingCount=%d, want 5", got.PendingCount)
	}
	if got.CursorAt != nil {
		t.Fatalf("cursorAt=%v, want nil (zero cursor must be omitted)", got.CursorAt)
	}
	if got.OldestPendingAt == nil || got.NewestPendingAt == nil {
		t.Fatalf("oldest/newest pending must be populated; got oldest=%v newest=%v", got.OldestPendingAt, got.NewestPendingAt)
	}
	if !got.OldestPendingAt.Equal(base) {
		t.Fatalf("oldestPendingAt=%v, want %v", got.OldestPendingAt, base)
	}
	wantNewest := base.Add(4 * time.Second)
	if !got.NewestPendingAt.Equal(wantNewest) {
		t.Fatalf("newestPendingAt=%v, want %v", got.NewestPendingAt, wantNewest)
	}
}

// TestAuditForwardStatus_CursorAtNewest_NoPending: when the cursor
// matches the newest entry, the next heartbeat would ship nothing —
// pendingCount must be 0 and the timestamp omits oldest/newest.
func TestAuditForwardStatus_CursorAtNewest_NoPending(t *testing.T) {
	base := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	l := seedDiskLogger(t, 4, base, "test.action")
	cursor := base.Add(3 * time.Second) // newest
	r := newAuditForwardRouter(fakeAuditCursorSource{at: cursor}, l, true)
	req := httptest.NewRequest(http.MethodGet, "/api/system/audit/forward-status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	got := decodeForwardStatus(t, rr.Body.Bytes())
	if got.PendingCount != 0 {
		t.Fatalf("pendingCount=%d, want 0; body=%s", got.PendingCount, rr.Body.String())
	}
	if got.CursorAt == nil || !got.CursorAt.Equal(cursor) {
		t.Fatalf("cursorAt=%v, want %v", got.CursorAt, cursor)
	}
	if got.OldestPendingAt != nil || got.NewestPendingAt != nil {
		t.Fatalf("oldest/newest pending must be nil when nothing pending; got oldest=%v newest=%v", got.OldestPendingAt, got.NewestPendingAt)
	}
}

// TestAuditForwardStatus_CursorMidway_PartialPending: cursor in the
// middle of the on-disk window — only entries strictly newer than the
// cursor count as pending. Mirrors the "newer than cursor" semantics
// the agent uses at heartbeat time.
func TestAuditForwardStatus_CursorMidway_PartialPending(t *testing.T) {
	base := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	l := seedDiskLogger(t, 6, base, "test.action") // entries at base+0..+5s
	// Cursor at base+2s — pending should be entries at base+3,+4,+5 (3 entries).
	cursor := base.Add(2 * time.Second)
	r := newAuditForwardRouter(fakeAuditCursorSource{at: cursor}, l, true)
	req := httptest.NewRequest(http.MethodGet, "/api/system/audit/forward-status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	got := decodeForwardStatus(t, rr.Body.Bytes())
	if got.PendingCount != 3 {
		t.Fatalf("pendingCount=%d, want 3", got.PendingCount)
	}
	wantOldest := base.Add(3 * time.Second)
	wantNewest := base.Add(5 * time.Second)
	if got.OldestPendingAt == nil || !got.OldestPendingAt.Equal(wantOldest) {
		t.Fatalf("oldestPendingAt=%v, want %v", got.OldestPendingAt, wantOldest)
	}
	if got.NewestPendingAt == nil || !got.NewestPendingAt.Equal(wantNewest) {
		t.Fatalf("newestPendingAt=%v, want %v", got.NewestPendingAt, wantNewest)
	}
}

// TestAuditForwardStatus_NilCursorSource_TreatedAsZero: a nil cursor
// source (dev path) must be treated as a zero-time cursor — the
// handler still serves a useful response.
func TestAuditForwardStatus_NilCursorSource_TreatedAsZero(t *testing.T) {
	base := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	l := seedDiskLogger(t, 2, base, "test.action")
	r := newAuditForwardRouter(nil, l, true)
	req := httptest.NewRequest(http.MethodGet, "/api/system/audit/forward-status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	got := decodeForwardStatus(t, rr.Body.Bytes())
	if got.CursorAt != nil {
		t.Fatalf("cursorAt=%v, want nil", got.CursorAt)
	}
	if got.PendingCount != 2 {
		t.Fatalf("pendingCount=%d, want 2", got.PendingCount)
	}
}

// TestAuditForwardStatus_HeadersAndOK: smoke test that the response is
// JSON 200 with the canonical content-type so reverse proxies / clients
// don't have to negotiate.
func TestAuditForwardStatus_HeadersAndOK(t *testing.T) {
	r := newAuditForwardRouter(nil, configlog.LoggerNoop{}, true)
	req := httptest.NewRequest(http.MethodGet, "/api/system/audit/forward-status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type=%q, want application/json", got)
	}
}

// errLogger is a Logger whose List always returns an error so we can
// exercise the 500 path. Append/Close are no-ops.
type errLogger struct{ err error }

func (e errLogger) Append(_ context.Context, _ configlog.Entry) error  { return nil }
func (e errLogger) List(_ configlog.ListOptions) ([]configlog.Entry, error) {
	return nil, e.err
}
func (e errLogger) Close() error { return nil }

// TestAuditForwardStatus_ListError500: when the underlying logger
// errors on List, the handler must surface a 500 — silently returning
// 0 pending would mask a real failure.
func TestAuditForwardStatus_ListError500(t *testing.T) {
	r := newAuditForwardRouter(nil, errLogger{err: context.DeadlineExceeded}, true)
	req := httptest.NewRequest(http.MethodGet, "/api/system/audit/forward-status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500; body=%s", rr.Code, rr.Body.String())
	}
}
