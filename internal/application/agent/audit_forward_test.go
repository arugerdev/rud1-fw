package agent

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/audit/configlog"
)

// TestAuditEntryFingerprint_StableForSameFields: two entries that differ
// only in Previous/Next produce the same fingerprint. We deliberately do
// NOT include those in the hash — they are operator-supplied free-form
// values and would defeat the de-dup goal.
func TestAuditEntryFingerprint_StableForSameFields(t *testing.T) {
	a := configlog.Entry{At: 1700000000, Action: "system.timezone.set", Actor: "operator", ResourceID: "", Previous: map[string]any{"tz": "UTC"}, Next: map[string]any{"tz": "Europe/Madrid"}}
	b := configlog.Entry{At: 1700000000, Action: "system.timezone.set", Actor: "operator", ResourceID: "", Previous: map[string]any{"tz": "UTC"}, Next: map[string]any{"tz": "Europe/Berlin"}}
	if auditEntryFingerprint(a) != auditEntryFingerprint(b) {
		t.Fatalf("fingerprint must ignore Previous/Next: got %s vs %s",
			auditEntryFingerprint(a), auditEntryFingerprint(b))
	}
}

// TestAuditEntryFingerprint_DifferentForAt: same action + actor at
// different timestamps must hash differently.
func TestAuditEntryFingerprint_DifferentForAt(t *testing.T) {
	a := configlog.Entry{At: 1700000000, Action: "x", Actor: "operator"}
	b := configlog.Entry{At: 1700000001, Action: "x", Actor: "operator"}
	if auditEntryFingerprint(a) == auditEntryFingerprint(b) {
		t.Fatalf("fingerprint must include At")
	}
}

// TestAuditEntryFingerprint_DifferentForAction
func TestAuditEntryFingerprint_DifferentForAction(t *testing.T) {
	a := configlog.Entry{At: 1700000000, Action: "x", Actor: "operator"}
	b := configlog.Entry{At: 1700000000, Action: "y", Actor: "operator"}
	if auditEntryFingerprint(a) == auditEntryFingerprint(b) {
		t.Fatalf("fingerprint must include Action")
	}
}

// TestBuildHeartbeatAudit_NilLogger_ReturnsNil verifies the no-op path
// when the agent could not open a disk-backed audit logger (e.g. the
// data dir was read-only at boot).
func TestBuildHeartbeatAudit_NilLogger_ReturnsNil(t *testing.T) {
	a := &Agent{auditLog: nil}
	block, fp := a.buildHeartbeatAudit()
	if block != nil {
		t.Fatalf("nil logger must yield nil block, got %#v", block)
	}
	if fp != "" {
		t.Fatalf("nil logger must yield empty fp, got %q", fp)
	}
}

// TestBuildHeartbeatAudit_EmptyLog_ReturnsNil: a freshly-constructed
// logger with no entries must omit the block — there is nothing to ship.
func TestBuildHeartbeatAudit_EmptyLog_ReturnsNil(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	l, err := configlog.New(dir, configlog.Options{})
	if err != nil {
		t.Fatalf("configlog.New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	a := &Agent{auditLog: l}
	block, fp := a.buildHeartbeatAudit()
	if block != nil || fp != "" {
		t.Fatalf("empty log must yield (nil, \"\"), got (%v, %q)", block, fp)
	}
}

// TestBuildHeartbeatAudit_FirstShipReturnsRollingWindow: with N entries
// in the log and no prior fingerprint, the helper must return all N
// (newest-first) and the newest fingerprint.
func TestBuildHeartbeatAudit_FirstShipReturnsRollingWindow(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	l, err := configlog.New(dir, configlog.Options{})
	if err != nil {
		t.Fatalf("configlog.New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	ctx := context.Background()
	for i := int64(1); i <= 5; i++ {
		if err := l.Append(ctx, configlog.Entry{At: 1_700_000_000 + i, Action: "x", Actor: "operator", OK: true}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	a := &Agent{auditLog: l}
	block, fp := a.buildHeartbeatAudit()
	if block == nil {
		t.Fatalf("expected non-nil block on first ship")
	}
	if len(block.Entries) != 5 {
		t.Fatalf("want 5 entries, got %d", len(block.Entries))
	}
	if block.Entries[0].At != 1_700_000_005 {
		t.Fatalf("entries must be newest-first; got first.At=%d", block.Entries[0].At)
	}
	if block.LastAt != 1_700_000_005 {
		t.Fatalf("LastAt must equal newest entry; got %d", block.LastAt)
	}
	wantFp := auditEntryFingerprint(configlog.Entry{At: 1_700_000_005, Action: "x", Actor: "operator"})
	if fp != wantFp {
		t.Fatalf("fingerprint mismatch: want %q got %q", wantFp, fp)
	}
}

// TestBuildHeartbeatAudit_SteadyStateOmitted: when the newest entry's
// fingerprint matches the last-forwarded one, the helper returns
// (nil, "") so the heartbeat omits the block.
func TestBuildHeartbeatAudit_SteadyStateOmitted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	l, err := configlog.New(dir, configlog.Options{})
	if err != nil {
		t.Fatalf("configlog.New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if err := l.Append(context.Background(), configlog.Entry{At: 1_700_000_001, Action: "x", Actor: "operator", OK: true}); err != nil {
		t.Fatalf("append: %v", err)
	}
	a := &Agent{auditLog: l}
	// Pretend we already shipped this one.
	a.lastForwardedAuditFp = auditEntryFingerprint(configlog.Entry{At: 1_700_000_001, Action: "x", Actor: "operator"})

	block, fp := a.buildHeartbeatAudit()
	if block != nil || fp != "" {
		t.Fatalf("steady state must yield (nil, \"\"), got (%v, %q)", block, fp)
	}
}

// TestBuildHeartbeatAudit_NewEntryRetransmits: a new entry appended
// after a successful ship must trigger re-emission and the cap of
// MaxHBAuditEntries must be respected.
func TestBuildHeartbeatAudit_NewEntryRetransmits(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	l, err := configlog.New(dir, configlog.Options{})
	if err != nil {
		t.Fatalf("configlog.New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	ctx := context.Background()
	// Append 20 entries — more than MaxHBAuditEntries (16).
	base := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC).Unix()
	for i := int64(0); i < 20; i++ {
		if err := l.Append(ctx, configlog.Entry{At: base + i, Action: "x", Actor: "operator", OK: true}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	a := &Agent{auditLog: l}
	block, fp := a.buildHeartbeatAudit()
	if block == nil || fp == "" {
		t.Fatalf("first ship must return non-nil block")
	}
	// Cap respected.
	if len(block.Entries) != 16 {
		t.Fatalf("want 16 entries (capped), got %d", len(block.Entries))
	}
	// Newest entry first.
	if block.Entries[0].At != base+19 {
		t.Fatalf("want newest entry first; got %d", block.Entries[0].At)
	}
	// Commit fingerprint.
	a.lastForwardedAuditFp = fp
	// Same state ⇒ omitted.
	if b2, f2 := a.buildHeartbeatAudit(); b2 != nil || f2 != "" {
		t.Fatalf("after commit, steady state must omit; got (%v, %q)", b2, f2)
	}

	// New entry ⇒ re-emit.
	if err := l.Append(ctx, configlog.Entry{At: base + 100, Action: "y", Actor: "operator", OK: true}); err != nil {
		t.Fatalf("append y: %v", err)
	}
	b3, f3 := a.buildHeartbeatAudit()
	if b3 == nil || f3 == "" {
		t.Fatalf("new entry must trigger re-emit")
	}
	if b3.Entries[0].At != base+100 || b3.Entries[0].Action != "y" {
		t.Fatalf("newest entry must be the new one; got %#v", b3.Entries[0])
	}
}
