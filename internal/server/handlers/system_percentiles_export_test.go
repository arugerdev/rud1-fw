package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/sysstat"
)

// TestSystemPercentilesExport_NoHistoryReturns503 asserts the handler reports
// 503 with a JSON `{error: "history unavailable"}` body when the collector
// has no HistoryStore wired — matches the spec and mirrors the
// RevocationsExport 503 behaviour for unwired backends.
func TestSystemPercentilesExport_NoHistoryReturns503(t *testing.T) {
	// Bare collector — SetHistoryStore was never called, so History() == nil.
	h := NewSystemPercentilesExportHandler(&sysstat.Collector{})

	req := httptest.NewRequest(http.MethodGet, "/api/percentiles/export", nil)
	rr := httptest.NewRecorder()
	h.Export(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 — body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, rr.Body.String())
	}
	if body["error"] != "history unavailable" {
		t.Fatalf("error = %q, want %q", body["error"], "history unavailable")
	}
}

// TestSystemPercentilesExport_HappyPath_JSONLChronological appends three
// fake samples to a real disk-backed HistoryStore, calls the export, and
// asserts:
//
//  1. Content-Type / Content-Disposition headers are set correctly,
//  2. the body parses as JSONL,
//  3. samples come out oldest-first (HistoryStore native order).
func TestSystemPercentilesExport_HappyPath_JSONLChronological(t *testing.T) {
	dir := t.TempDir()
	store, err := sysstat.NewHistoryStore(dir)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}

	// Three samples within the last few minutes so the default 24h window
	// covers them. Use Append with explicit `at` so the test is deterministic.
	now := time.Now().UTC().Truncate(time.Second)
	samples := []struct {
		at  time.Time
		cpu float64
		ld  float64
	}{
		{now.Add(-3 * time.Minute), 12.5, 0.10},
		{now.Add(-2 * time.Minute), 25.0, 0.20},
		{now.Add(-1 * time.Minute), 37.5, 0.30},
	}
	for i, s := range samples {
		if err := store.Append(s.at, s.cpu, s.ld); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	col := &sysstat.Collector{}
	col.SetHistoryStore(store)
	h := NewSystemPercentilesExportHandler(col)

	req := httptest.NewRequest(http.MethodGet, "/api/percentiles/export", nil)
	rr := httptest.NewRecorder()
	h.Export(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/x-ndjson" {
		t.Fatalf("Content-Type = %q, want application/x-ndjson", got)
	}
	cd := rr.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "rud1-percentiles-") || !strings.Contains(cd, ".jsonl") {
		t.Fatalf("Content-Disposition = %q, want rud1-percentiles-*.jsonl", cd)
	}

	// Parse JSONL body; verify count + chronological order.
	var got []percentilesExportEntry
	sc := bufio.NewScanner(strings.NewReader(rr.Body.String()))
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e percentilesExportEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("unmarshal line %q: %v", string(line), err)
		}
		got = append(got, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != len(samples) {
		t.Fatalf("got %d entries, want %d (body=%s)", len(got), len(samples), rr.Body.String())
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].At >= got[i].At {
			t.Fatalf("entries not chronological at %d: %d >= %d", i, got[i-1].At, got[i].At)
		}
	}
	if got[0].CPUPct != samples[0].cpu || got[len(got)-1].CPUPct != samples[len(samples)-1].cpu {
		t.Fatalf("payload mismatch: got first cpu=%v last cpu=%v, want %v/%v",
			got[0].CPUPct, got[len(got)-1].CPUPct, samples[0].cpu, samples[len(samples)-1].cpu)
	}
}

// TestSystemPercentilesExport_RejectsInvertedWindow asserts that a since>=until
// query is rejected with 400 before any sample is read — cheap client-bug guard
// matching the RevocationsExport behaviour.
func TestSystemPercentilesExport_RejectsInvertedWindow(t *testing.T) {
	dir := t.TempDir()
	store, err := sysstat.NewHistoryStore(dir)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	col := &sysstat.Collector{}
	col.SetHistoryStore(store)
	h := NewSystemPercentilesExportHandler(col)

	// since > until — must 400.
	url := "/api/percentiles/export?since=200&until=100"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	h.Export(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — body=%s", rr.Code, rr.Body.String())
	}
}

// TestSystemPercentilesExport_FormatJSONReturnsArray verifies the
// `format=json` variant emits a single valid JSON array (rather than NDJSON)
// and sets Content-Type accordingly. Same dataset as the JSONL happy path so
// the only thing under test is the format branch.
func TestSystemPercentilesExport_FormatJSONReturnsArray(t *testing.T) {
	dir := t.TempDir()
	store, err := sysstat.NewHistoryStore(dir)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	for i, off := range []time.Duration{-3 * time.Minute, -2 * time.Minute, -1 * time.Minute} {
		if err := store.Append(now.Add(off), float64(10*(i+1)), float64(i+1)*0.1); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	col := &sysstat.Collector{}
	col.SetHistoryStore(store)
	h := NewSystemPercentilesExportHandler(col)

	req := httptest.NewRequest(http.MethodGet, "/api/percentiles/export?format=json", nil)
	rr := httptest.NewRecorder()
	h.Export(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	cd := rr.Header().Get("Content-Disposition")
	if !strings.Contains(cd, ".json\"") {
		t.Fatalf("Content-Disposition = %q, want .json extension", cd)
	}

	// Whole body must round-trip as a JSON array.
	var arr []percentilesExportEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &arr); err != nil {
		t.Fatalf("unmarshal array: %v (body=%s)", err, rr.Body.String())
	}
	if len(arr) != 3 {
		t.Fatalf("got %d entries, want 3 — body=%s", len(arr), rr.Body.String())
	}
	// Sanity: chronological order preserved, payload sample matches.
	for i := 1; i < len(arr); i++ {
		if arr[i-1].At >= arr[i].At {
			t.Fatalf("entries not chronological at %d", i)
		}
	}
	if fmt.Sprintf("%.1f", arr[0].CPUPct) != "10.0" {
		t.Fatalf("first cpu = %v, want 10.0", arr[0].CPUPct)
	}
}
