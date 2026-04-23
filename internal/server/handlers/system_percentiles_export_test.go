package handlers

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
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

// TestSystemPercentilesExport_GzipWhenRequested asserts the iter-16 gzip knob:
// when the client sends Accept-Encoding: gzip the handler compresses the body
// transparently, advertises Content-Encoding/Vary headers, and appends ".gz"
// to the attachment filename so operators can tell the variants apart in a
// Downloads folder. The decoded payload must round-trip as the same JSONL the
// non-gzip path produces.
func TestSystemPercentilesExport_GzipWhenRequested(t *testing.T) {
	dir := t.TempDir()
	store, err := sysstat.NewHistoryStore(dir)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
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
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	h.Export(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := rr.Header().Get("Vary"); got != "Accept-Encoding" {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}
	cd := rr.Header().Get("Content-Disposition")
	if !strings.HasSuffix(strings.TrimSuffix(cd, `"`), ".jsonl.gz") {
		t.Fatalf("Content-Disposition = %q, want suffix .jsonl.gz", cd)
	}
	// The test record set is tiny; a gzip magic check is a cheap sanity
	// guard that the body bytes are actually deflated rather than leaked
	// plaintext.
	body := rr.Body.Bytes()
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Fatalf("body does not start with gzip magic: % x", body[:minInt(len(body), 4)])
	}

	// Decode and verify the JSONL content matches what the non-gzip path
	// would emit — compression must be byte-transparent to the payload.
	gzr, err := gzip.NewReader(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gzr.Close()
	plain, err := io.ReadAll(gzr)
	if err != nil {
		t.Fatalf("read decompressed: %v", err)
	}

	var got []percentilesExportEntry
	sc := bufio.NewScanner(strings.NewReader(string(plain)))
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
		t.Fatalf("got %d entries, want %d", len(got), len(samples))
	}
	if got[0].CPUPct != samples[0].cpu {
		t.Fatalf("first cpu = %v, want %v", got[0].CPUPct, samples[0].cpu)
	}
}

// TestSystemPercentilesExport_NoGzipWhenNotRequested locks in the
// backwards-compat side of the iter-16 knob: without Accept-Encoding the body
// is plain JSONL and the filename has no .gz suffix, so existing curl/browser
// clients see exactly the pre-iter-16 response bytes.
func TestSystemPercentilesExport_NoGzipWhenNotRequested(t *testing.T) {
	dir := t.TempDir()
	store, err := sysstat.NewHistoryStore(dir)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.Append(now.Add(-1*time.Minute), 42.0, 0.5); err != nil {
		t.Fatalf("Append: %v", err)
	}

	col := &sysstat.Collector{}
	col.SetHistoryStore(store)
	h := NewSystemPercentilesExportHandler(col)

	req := httptest.NewRequest(http.MethodGet, "/api/percentiles/export", nil)
	// No Accept-Encoding header.
	rr := httptest.NewRecorder()
	h.Export(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	cd := rr.Header().Get("Content-Disposition")
	if strings.Contains(cd, ".gz") {
		t.Fatalf("Content-Disposition = %q, must not contain .gz", cd)
	}
	// First non-empty byte must be '{' — plain JSONL, not gzip magic 0x1f.
	body := rr.Body.Bytes()
	if len(body) == 0 || body[0] != '{' {
		t.Fatalf("body[0] = %v, want '{' (plain JSONL)", body[0])
	}
}

// minInt is a tiny helper to avoid pulling math in just for a bounds clamp
// in one debug Printf.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
