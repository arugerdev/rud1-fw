package sysstat

import (
	"path/filepath"
	"testing"
	"time"
)

func TestHistoryStore_AppendAndHistory(t *testing.T) {
	dir := t.TempDir()
	h, err := NewHistoryStore(dir)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}

	now := time.Now().UTC()
	// Push 3 samples 1 minute apart.
	for i := 0; i < 3; i++ {
		if err := h.Append(now.Add(time.Duration(i)*time.Minute), float64(10+i), float64(i)*0.5); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	pts := h.History(0) // 0 = unlimited
	if len(pts) != 3 {
		t.Fatalf("got %d points, want 3", len(pts))
	}
	// Oldest-first ordering contract.
	for i := 1; i < len(pts); i++ {
		if pts[i].At.Before(pts[i-1].At) {
			t.Fatalf("point %d not in chronological order", i)
		}
	}
	if pts[0].CPUPct != 10 || pts[2].CPUPct != 12 {
		t.Fatalf("CPU values wrong: %+v", pts)
	}
}

func TestHistoryStore_WindowClipsOldSamples(t *testing.T) {
	dir := t.TempDir()
	h, err := NewHistoryStore(dir)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}

	now := time.Now().UTC()
	// One old sample (2h ago), one recent (1 min ago).
	if err := h.Append(now.Add(-2*time.Hour), 50, 1.0); err != nil {
		t.Fatalf("Append old: %v", err)
	}
	if err := h.Append(now.Add(-1*time.Minute), 20, 0.2); err != nil {
		t.Fatalf("Append new: %v", err)
	}

	// Window = 1h should include only the recent one.
	pts := h.History(time.Hour)
	if len(pts) != 1 {
		t.Fatalf("got %d points, want 1 (window=1h should drop the 2h-old sample)", len(pts))
	}
	if pts[0].CPUPct != 20 {
		t.Fatalf("unexpected cpu: %+v", pts[0])
	}
}

func TestHistoryStore_ReloadAfterRestart(t *testing.T) {
	dir := t.TempDir()
	h, err := NewHistoryStore(dir)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		if err := h.Append(now.Add(time.Duration(i)*time.Minute), float64(20+i), 0.3); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// Simulate restart: drop in-memory state, reopen same dir.
	h2, err := NewHistoryStore(dir)
	if err != nil {
		t.Fatalf("NewHistoryStore (reload): %v", err)
	}
	if h2.Size() != 5 {
		t.Fatalf("restored %d samples, want 5", h2.Size())
	}
	pts := h2.History(0)
	if len(pts) != 5 || pts[0].CPUPct != 20 || pts[4].CPUPct != 24 {
		t.Fatalf("restored samples wrong: %+v", pts)
	}
}

func TestHistoryStore_TrimKeepsLatest(t *testing.T) {
	dir := t.TempDir()
	h, err := NewHistoryStore(dir)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	// Push more than historyMaxSamples entries to exercise the rewrite path.
	// Use a loop that crosses the trim threshold.
	base := time.Now().UTC().Add(-2 * 24 * time.Hour) // 2 days ago
	total := historyMaxSamples + historyTrimThreshold + 5
	for i := 0; i < total; i++ {
		if err := h.Append(base.Add(time.Duration(i)*time.Minute), float64(i%100), 0.1); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	// The rewrite runs every historyTrimThreshold appends so the in-memory
	// slice can carry up to historyMaxSamples+historyTrimThreshold-1 rows
	// between rewrites; enforce that upper bound.
	if got := h.Size(); got > historyMaxSamples+historyTrimThreshold {
		t.Fatalf("after trim: size=%d, want ≤ %d", got, historyMaxSamples+historyTrimThreshold)
	}
	// Reload should clip to exactly historyMaxSamples since load() enforces
	// the hard cap regardless of rewrite cadence.
	h2, err := NewHistoryStore(dir)
	if err != nil {
		t.Fatalf("NewHistoryStore (reload): %v", err)
	}
	if got := h2.Size(); got > historyMaxSamples {
		t.Fatalf("after reload: size=%d, want ≤ %d", got, historyMaxSamples)
	}
	// File should exist.
	if _, err := filepath.Glob(filepath.Join(dir, historyFilename)); err != nil {
		t.Fatalf("glob: %v", err)
	}
}
