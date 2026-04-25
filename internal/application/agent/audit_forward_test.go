package agent

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/audit/auditcursor"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/audit/configlog"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/cloud"
)

// newTestAgentWithAudit wires a fresh on-disk audit logger and cursor
// store under t.TempDir() so each test exercises the same code path
// the production agent uses, without sharing global state across tests.
// The cursor is left zero by default so the test starts in a "first
// boot, no history yet" state — individual tests can override
// a.auditCursor or pre-populate the disk file as needed.
func newTestAgentWithAudit(t *testing.T) (*Agent, string) {
	t.Helper()
	root := t.TempDir()
	auditDir := filepath.Join(root, "audit")
	cursorDir := filepath.Join(root, "cursor")
	l, err := configlog.New(auditDir, configlog.Options{})
	if err != nil {
		t.Fatalf("configlog.New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	cs, err := auditcursor.New(cursorDir)
	if err != nil {
		t.Fatalf("auditcursor.New: %v", err)
	}
	a := &Agent{auditLog: l, auditCursorStore: cs}
	return a, cursorDir
}

// TestBuildHeartbeatAudit_NilLogger_ReturnsNil verifies the no-op path
// when the agent could not open a disk-backed audit logger (e.g. the
// data dir was read-only at boot).
func TestBuildHeartbeatAudit_NilLogger_ReturnsNil(t *testing.T) {
	a := &Agent{auditLog: nil}
	block, newest := a.buildHeartbeatAudit()
	if block != nil {
		t.Fatalf("nil logger must yield nil block, got %#v", block)
	}
	if !newest.IsZero() {
		t.Fatalf("nil logger must yield zero time, got %v", newest)
	}
}

// TestBuildHeartbeatAudit_EmptyLog_ReturnsNil: a freshly-constructed
// logger with no entries must omit the block — there is nothing to ship.
func TestBuildHeartbeatAudit_EmptyLog_ReturnsNil(t *testing.T) {
	a, _ := newTestAgentWithAudit(t)
	block, newest := a.buildHeartbeatAudit()
	if block != nil || !newest.IsZero() {
		t.Fatalf("empty log must yield (nil, zero), got (%v, %v)", block, newest)
	}
}

// TestBuildHeartbeatAudit_FirstShipDelivers5: with the cursor at zero
// and 5 entries on disk, the helper returns all 5 oldest-first and the
// newest timestamp.
func TestBuildHeartbeatAudit_FirstShipDelivers5(t *testing.T) {
	a, _ := newTestAgentWithAudit(t)
	ctx := context.Background()
	for i := int64(1); i <= 5; i++ {
		if err := a.auditLog.Append(ctx, configlog.Entry{At: 1_700_000_000 + i, Action: "x", Actor: "operator", OK: true}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	block, newest := a.buildHeartbeatAudit()
	if block == nil {
		t.Fatalf("expected non-nil block on first ship")
	}
	if len(block.Entries) != 5 {
		t.Fatalf("want 5 entries, got %d", len(block.Entries))
	}
	if block.Entries[0].At != 1_700_000_001 {
		t.Fatalf("entries must be oldest-first; got first.At=%d", block.Entries[0].At)
	}
	if block.Entries[4].At != 1_700_000_005 {
		t.Fatalf("entries must be oldest-first; got last.At=%d", block.Entries[4].At)
	}
	if block.LastAt != 1_700_000_005 {
		t.Fatalf("LastAt must equal newest entry; got %d", block.LastAt)
	}
	if newest.Unix() != 1_700_000_005 {
		t.Fatalf("newest cursor must equal newest entry; got %d", newest.Unix())
	}
}

// TestBuildHeartbeatAudit_DeltaAfterCursor: cursor at the timestamp of
// entry #5 ⇒ subsequent build returns only entries strictly newer.
func TestBuildHeartbeatAudit_DeltaAfterCursor(t *testing.T) {
	a, _ := newTestAgentWithAudit(t)
	ctx := context.Background()
	for i := int64(1); i <= 5; i++ {
		if err := a.auditLog.Append(ctx, configlog.Entry{At: 1_700_000_000 + i, Action: "x", Actor: "operator", OK: true}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	// First ship.
	block, newest := a.buildHeartbeatAudit()
	if block == nil || len(block.Entries) != 5 {
		t.Fatalf("first ship: want 5 entries, got %v", block)
	}
	a.commitAuditCursor(newest)

	// Add 3 more.
	for i := int64(6); i <= 8; i++ {
		if err := a.auditLog.Append(ctx, configlog.Entry{At: 1_700_000_000 + i, Action: "x", Actor: "operator", OK: true}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	block2, newest2 := a.buildHeartbeatAudit()
	if block2 == nil {
		t.Fatalf("delta ship must return non-nil block")
	}
	if len(block2.Entries) != 3 {
		t.Fatalf("want 3 entries (delta only), got %d", len(block2.Entries))
	}
	if block2.Entries[0].At != 1_700_000_006 {
		t.Fatalf("delta must start at first new entry; got %d", block2.Entries[0].At)
	}
	if newest2.Unix() != 1_700_000_008 {
		t.Fatalf("newest cursor mismatch; got %d", newest2.Unix())
	}
}

// TestBuildHeartbeatAudit_SteadyStateOmitted: after committing the
// cursor, a build with no new entries returns (nil, zero).
func TestBuildHeartbeatAudit_SteadyStateOmitted(t *testing.T) {
	a, _ := newTestAgentWithAudit(t)
	if err := a.auditLog.Append(context.Background(), configlog.Entry{At: 1_700_000_001, Action: "x", Actor: "operator", OK: true}); err != nil {
		t.Fatalf("append: %v", err)
	}
	block, newest := a.buildHeartbeatAudit()
	if block == nil {
		t.Fatalf("first ship must return block")
	}
	a.commitAuditCursor(newest)

	block2, newest2 := a.buildHeartbeatAudit()
	if block2 != nil || !newest2.IsZero() {
		t.Fatalf("steady state must yield (nil, zero), got (%v, %v)", block2, newest2)
	}
}

// TestBuildHeartbeatAudit_BurstOf30_DrainsInTwoTicks: the per-tick cap
// is MaxHBAuditEntries=16 — a 30-entry burst must ship the oldest 16
// first, advance the cursor, then ship the remaining 14 on the next
// build call.
func TestBuildHeartbeatAudit_BurstOf30_DrainsInTwoTicks(t *testing.T) {
	a, _ := newTestAgentWithAudit(t)
	ctx := context.Background()
	base := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC).Unix()
	for i := int64(0); i < 30; i++ {
		if err := a.auditLog.Append(ctx, configlog.Entry{At: base + i, Action: "x", Actor: "operator", OK: true}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// Tick 1: ships the 16 oldest.
	block, newest := a.buildHeartbeatAudit()
	if block == nil {
		t.Fatalf("tick 1: expected non-nil block")
	}
	if len(block.Entries) != cloud.MaxHBAuditEntries {
		t.Fatalf("tick 1: want %d entries, got %d", cloud.MaxHBAuditEntries, len(block.Entries))
	}
	if block.Entries[0].At != base+0 {
		t.Fatalf("tick 1: must start at oldest; got %d", block.Entries[0].At)
	}
	if block.Entries[len(block.Entries)-1].At != base+15 {
		t.Fatalf("tick 1: must end at base+15; got %d", block.Entries[len(block.Entries)-1].At)
	}
	if newest.Unix() != base+15 {
		t.Fatalf("tick 1: newest cursor mismatch; got %d", newest.Unix())
	}
	a.commitAuditCursor(newest)

	// Tick 2: ships the remaining 14.
	block2, newest2 := a.buildHeartbeatAudit()
	if block2 == nil {
		t.Fatalf("tick 2: expected non-nil block")
	}
	if len(block2.Entries) != 14 {
		t.Fatalf("tick 2: want 14 entries, got %d", len(block2.Entries))
	}
	if block2.Entries[0].At != base+16 {
		t.Fatalf("tick 2: must start at base+16; got %d", block2.Entries[0].At)
	}
	if block2.Entries[13].At != base+29 {
		t.Fatalf("tick 2: must end at base+29; got %d", block2.Entries[13].At)
	}
	if newest2.Unix() != base+29 {
		t.Fatalf("tick 2: newest cursor mismatch; got %d", newest2.Unix())
	}
	a.commitAuditCursor(newest2)

	// Tick 3: caught up.
	block3, newest3 := a.buildHeartbeatAudit()
	if block3 != nil || !newest3.IsZero() {
		t.Fatalf("tick 3: must omit; got (%v, %v)", block3, newest3)
	}
}

// TestBuildHeartbeatAudit_TransportFailure_CursorNotAdvanced: when the
// caller does NOT call commitAuditCursor (simulating a heartbeat that
// failed to send), the next build must return the same window.
func TestBuildHeartbeatAudit_TransportFailure_CursorNotAdvanced(t *testing.T) {
	a, _ := newTestAgentWithAudit(t)
	ctx := context.Background()
	for i := int64(1); i <= 3; i++ {
		if err := a.auditLog.Append(ctx, configlog.Entry{At: 1_700_000_000 + i, Action: "x", Actor: "operator", OK: true}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	// First build (success path stops here, no commit).
	block, newest := a.buildHeartbeatAudit()
	if block == nil || len(block.Entries) != 3 {
		t.Fatalf("first build: want 3 entries, got %v", block)
	}

	// Simulated transport failure: no commit. Cursor stays zero.
	if !a.auditCursor.IsZero() {
		t.Fatalf("cursor must remain zero on transport failure; got %v", a.auditCursor)
	}

	// Replay: must return the same 3 entries again.
	block2, newest2 := a.buildHeartbeatAudit()
	if block2 == nil || len(block2.Entries) != 3 {
		t.Fatalf("replay: want 3 entries, got %v", block2)
	}
	if block2.Entries[0].At != 1_700_000_001 || block2.Entries[2].At != 1_700_000_003 {
		t.Fatalf("replay: entries do not match first build")
	}
	if !newest.Equal(newest2) {
		t.Fatalf("replay: newest cursor must match; got %v vs %v", newest, newest2)
	}
}

// TestCommitAuditCursor_PersistsToDisk verifies the round-trip via the
// disk file: a Commit + new Load must return the same timestamp.
func TestCommitAuditCursor_PersistsToDisk(t *testing.T) {
	a, dir := newTestAgentWithAudit(t)
	want := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	a.commitAuditCursor(want)

	// Re-open the cursor store from the same dir and Load.
	cs2, err := auditcursor.New(dir)
	if err != nil {
		t.Fatalf("re-New: %v", err)
	}
	got, exists, err := cs2.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !exists {
		t.Fatalf("expected exists=true after commit")
	}
	if !got.Equal(want) {
		t.Fatalf("round-trip mismatch: want %v got %v", want, got)
	}
}

// TestBuildHeartbeatAudit_FirstBootDefaultsToNow_NoHistoricalSpam:
// a fresh agent on an upgraded device whose disk audit log already
// contains historical entries must NOT spam-ship them on first
// heartbeat. We simulate the New() init path by setting
// a.auditCursor = time.Now() before calling buildHeartbeatAudit.
func TestBuildHeartbeatAudit_FirstBootDefaultsToNow_NoHistoricalSpam(t *testing.T) {
	a, _ := newTestAgentWithAudit(t)
	ctx := context.Background()
	// Pre-existing on-disk history (e.g. from before the upgrade).
	old := time.Now().Add(-24 * time.Hour).Unix()
	for i := int64(0); i < 5; i++ {
		if err := a.auditLog.Append(ctx, configlog.Entry{At: old + i, Action: "x", Actor: "operator", OK: true}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	// Mirror New()'s first-boot default.
	a.auditCursor = time.Now()

	block, newest := a.buildHeartbeatAudit()
	if block != nil || !newest.IsZero() {
		t.Fatalf("first-boot cursor must suppress historical entries; got (%v, %v)", block, newest)
	}
}
