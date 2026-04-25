package agent

import (
	"testing"
	"time"
)

// TestShouldEmitTimeHealth_FirstCall: when lastSent is the zero time (no
// heartbeat has carried a snapshot yet) the throttle MUST allow the
// emission unconditionally — the cloud's banner needs current state on
// the very first beat after startup.
func TestShouldEmitTimeHealth_FirstCall(t *testing.T) {
	now := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	if !shouldEmitTimeHealth(now, time.Time{}, "", "fp-a") {
		t.Fatalf("first call (zero lastSent) must emit, got false")
	}
}

// TestShouldEmitTimeHealth_SameFingerprintWithinHour: nothing has
// changed and the keepalive window hasn't elapsed → suppress.
func TestShouldEmitTimeHealth_SameFingerprintWithinHour(t *testing.T) {
	now := time.Date(2026, 4, 25, 10, 30, 0, 0, time.UTC)
	last := now.Add(-15 * time.Minute)
	if shouldEmitTimeHealth(now, last, "fp-a", "fp-a") {
		t.Fatalf("same fingerprint within keepalive window must suppress, got true")
	}
}

// TestShouldEmitTimeHealth_SameFingerprintPastHour: even with no state
// change, ship the block once an hour so the cloud can detect a hung
// agent that's no longer producing heartbeats with telemetry.
func TestShouldEmitTimeHealth_SameFingerprintPastHour(t *testing.T) {
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	last := now.Add(-2 * time.Hour)
	if !shouldEmitTimeHealth(now, last, "fp-a", "fp-a") {
		t.Fatalf("keepalive past 1h must emit, got false")
	}
}

// TestShouldEmitTimeHealth_FingerprintBoundary: at exactly the keepalive
// interval the predicate fires (>=, not >). Pinning the boundary so a
// future refactor doesn't accidentally drift the threshold.
func TestShouldEmitTimeHealth_FingerprintBoundary(t *testing.T) {
	now := time.Date(2026, 4, 25, 11, 0, 0, 0, time.UTC)
	last := now.Add(-timeHealthKeepaliveInterval)
	if !shouldEmitTimeHealth(now, last, "fp-a", "fp-a") {
		t.Fatalf("at exactly the keepalive boundary must emit (>=), got false")
	}
}

// TestShouldEmitTimeHealth_DifferentFingerprint: any state change must
// emit immediately, regardless of the keepalive timer.
func TestShouldEmitTimeHealth_DifferentFingerprint(t *testing.T) {
	now := time.Date(2026, 4, 25, 10, 5, 0, 0, time.UTC)
	last := now.Add(-30 * time.Second)
	if !shouldEmitTimeHealth(now, last, "fp-a", "fp-b") {
		t.Fatalf("rising-edge fingerprint diff must emit, got false")
	}
}

// TestFingerprintTimeHealth_WarningOrderStable: two snapshots whose
// warning slices contain the same elements in different order MUST hash
// to the same fingerprint. Without canonical sorting we'd ship a
// redundant block every time the underlying source rearranged its
// warnings (which the time-health code does append in a fixed sequence
// today, but tomorrow might not).
func TestFingerprintTimeHealth_WarningOrderStable(t *testing.T) {
	a := timeHealthSnapshot{
		Timezone:       "Europe/Madrid",
		TimezoneSource: "timedatectl",
		Warnings:       []string{"NTP not synced", "timesyncd inactive"},
	}
	b := timeHealthSnapshot{
		Timezone:       "Europe/Madrid",
		TimezoneSource: "timedatectl",
		Warnings:       []string{"timesyncd inactive", "NTP not synced"},
	}
	fa := fingerprintTimeHealth(a)
	fb := fingerprintTimeHealth(b)
	if fa != fb {
		t.Fatalf("warning order must not affect fingerprint:\n a=%q\n b=%q", fa, fb)
	}
}

// TestFingerprintTimeHealth_DistinguishesFields: each meaningful field
// flips the fingerprint when changed. We don't enumerate every possible
// pair (combinatorial blowup); instead we vary one field at a time off
// a baseline and assert each variation produces a different hash.
func TestFingerprintTimeHealth_DistinguishesFields(t *testing.T) {
	base := timeHealthSnapshot{
		Timezone:        "UTC",
		TimezoneSource:  "fallback",
		IsUTC:           true,
		NTPEnabled:      false,
		NTPSynchronized: false,
		Warnings:        nil,
	}
	baseFp := fingerprintTimeHealth(base)

	mutations := map[string]timeHealthSnapshot{
		"tz changed":        func() timeHealthSnapshot { c := base; c.Timezone = "Europe/Madrid"; return c }(),
		"tzSource changed":  func() timeHealthSnapshot { c := base; c.TimezoneSource = "timedatectl"; return c }(),
		"isUTC flipped":     func() timeHealthSnapshot { c := base; c.IsUTC = false; return c }(),
		"ntpEnabled flip":   func() timeHealthSnapshot { c := base; c.NTPEnabled = true; return c }(),
		"ntpSync flipped":   func() timeHealthSnapshot { c := base; c.NTPSynchronized = true; return c }(),
		"warning appeared":  func() timeHealthSnapshot { c := base; c.Warnings = []string{"x"}; return c }(),
	}
	for name, mut := range mutations {
		got := fingerprintTimeHealth(mut)
		if got == baseFp {
			t.Errorf("%s: fingerprint unchanged (%q)", name, got)
		}
	}
}

// TestBuildTimeHealthBlock_FirstCallEmits: confirms the integration
// between fingerprintTimeHealth and shouldEmitTimeHealth — first call
// emits a block, populates CapturedAt as RFC3339 UTC, and computes a
// non-empty fingerprint.
func TestBuildTimeHealthBlock_FirstCallEmits(t *testing.T) {
	captured := time.Date(2026, 4, 25, 12, 34, 56, 0, time.UTC)
	now := captured
	snap := timeHealthSnapshot{
		Timezone:       "Europe/Madrid",
		TimezoneSource: "timedatectl",
		IsUTC:          false,
		NTPEnabled:     true,
		NTPSynchronized: true,
	}
	block, fp, emit := buildTimeHealthBlock(snap, captured, now, time.Time{}, "")
	if !emit {
		t.Fatalf("first call must emit")
	}
	if block == nil {
		t.Fatalf("emit=true but block=nil")
	}
	if fp == "" {
		t.Fatalf("fingerprint must be non-empty")
	}
	if block.CapturedAt != "2026-04-25T12:34:56Z" {
		t.Fatalf("CapturedAt = %q, want RFC3339 UTC", block.CapturedAt)
	}
	if block.Warnings != nil {
		t.Fatalf("Warnings must be nil when snapshot has none (omitempty), got %v", block.Warnings)
	}
}

// TestBuildTimeHealthBlock_SuppressedWhenUnchanged: same fingerprint,
// inside the keepalive window → block is nil and emit=false. The caller
// uses these flags to decide whether to set the heartbeat field AND
// whether to advance the throttle bookkeeping.
func TestBuildTimeHealthBlock_SuppressedWhenUnchanged(t *testing.T) {
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	last := now.Add(-10 * time.Minute)
	snap := timeHealthSnapshot{
		Timezone:       "UTC",
		TimezoneSource: "fallback",
		IsUTC:          true,
	}
	prevFp := fingerprintTimeHealth(snap)
	block, _, emit := buildTimeHealthBlock(snap, now, now, last, prevFp)
	if emit {
		t.Fatalf("identical snapshot within keepalive window must suppress")
	}
	if block != nil {
		t.Fatalf("emit=false but block non-nil: %+v", block)
	}
}
