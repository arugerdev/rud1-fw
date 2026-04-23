package handlers

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/sysstat/uptime"
)

// TestSystemUptimeEventsExport_NoStoreReturns503 asserts the handler reports
// 503 with a JSON `{error: "uptime events unavailable"}` body when the store
// is nil — matches the live /api/system/uptime-events behaviour for an unwired
// backend.
func TestSystemUptimeEventsExport_NoStoreReturns503(t *testing.T) {
	h := NewSystemUptimeEventsExportHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/system/uptime-events/export", nil)
	rr := httptest.NewRecorder()
	h.Export(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 — body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, rr.Body.String())
	}
	if body["error"] != "uptime events unavailable" {
		t.Fatalf("error = %q, want %q", body["error"], "uptime events unavailable")
	}
}

// TestSystemUptimeEventsExport_HappyPath_JSONLChronological appends three
// events to a disk-backed store, calls the export, and asserts:
//
//  1. Content-Type / Content-Disposition headers are set correctly,
//  2. the body parses as JSONL,
//  3. events come out oldest-first (audit-log convention — opposite of the
//     List() newest-first order).
func TestSystemUptimeEventsExport_HappyPath_JSONLChronological(t *testing.T) {
	dir := t.TempDir()
	store, err := uptime.OpenStoreAt(dir)
	if err != nil {
		t.Fatalf("OpenStoreAt: %v", err)
	}

	// Three events within the last few minutes so the default window covers
	// them. Fixed `At` values keep the test deterministic.
	now := time.Now().UTC().Truncate(time.Second)
	events := []uptime.Event{
		{At: now.Add(-3 * time.Minute), Kind: "boot", Uptime: 0, Reason: ""},
		{At: now.Add(-2 * time.Minute), Kind: "restart", Uptime: 42 * time.Second, Reason: "agent restart"},
		{At: now.Add(-1 * time.Minute), Kind: "shutdown", Uptime: 120 * time.Second, Reason: "signal"},
	}
	for i, ev := range events {
		if err := store.Append(ev); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	h := NewSystemUptimeEventsExportHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/api/system/uptime-events/export", nil)
	rr := httptest.NewRecorder()
	h.Export(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/x-ndjson" {
		t.Fatalf("Content-Type = %q, want application/x-ndjson", got)
	}
	cd := rr.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "rud1-uptime-") || !strings.Contains(cd, ".jsonl") {
		t.Fatalf("Content-Disposition = %q, want rud1-uptime-*.jsonl", cd)
	}

	var got []uptimeEventExportEntry
	sc := bufio.NewScanner(strings.NewReader(rr.Body.String()))
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e uptimeEventExportEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("unmarshal line %q: %v", string(line), err)
		}
		got = append(got, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != len(events) {
		t.Fatalf("got %d entries, want %d (body=%s)", len(got), len(events), rr.Body.String())
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].At >= got[i].At {
			t.Fatalf("entries not chronological at %d: %d >= %d", i, got[i-1].At, got[i].At)
		}
	}
	if got[0].Kind != "boot" || got[len(got)-1].Kind != "shutdown" {
		t.Fatalf("kind order = [%s..%s], want [boot..shutdown]", got[0].Kind, got[len(got)-1].Kind)
	}
	if got[1].UptimeSeconds != 42 || got[1].Reason != "agent restart" {
		t.Fatalf("middle event payload mismatch: %+v", got[1])
	}
}

// TestSystemUptimeEventsExport_RejectsInvertedWindow asserts that a
// since>=until query is rejected with 400 before any event is read.
func TestSystemUptimeEventsExport_RejectsInvertedWindow(t *testing.T) {
	dir := t.TempDir()
	store, err := uptime.OpenStoreAt(dir)
	if err != nil {
		t.Fatalf("OpenStoreAt: %v", err)
	}
	h := NewSystemUptimeEventsExportHandler(store)

	url := "/api/system/uptime-events/export?since=200&until=100"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	h.Export(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — body=%s", rr.Code, rr.Body.String())
	}
}

// TestSystemUptimeEventsExport_FormatJSONReturnsArray verifies the
// `format=json` variant emits a single valid JSON array (rather than NDJSON)
// and sets Content-Type accordingly. Same dataset as the JSONL happy path so
// the only thing under test is the format branch.
func TestSystemUptimeEventsExport_FormatJSONReturnsArray(t *testing.T) {
	dir := t.TempDir()
	store, err := uptime.OpenStoreAt(dir)
	if err != nil {
		t.Fatalf("OpenStoreAt: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	kinds := []string{"boot", "restart", "shutdown"}
	for i, off := range []time.Duration{-3 * time.Minute, -2 * time.Minute, -1 * time.Minute} {
		if err := store.Append(uptime.Event{
			At:     now.Add(off),
			Kind:   kinds[i],
			Uptime: time.Duration(i+1) * time.Second,
		}); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	h := NewSystemUptimeEventsExportHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/api/system/uptime-events/export?format=json", nil)
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

	var arr []uptimeEventExportEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &arr); err != nil {
		t.Fatalf("unmarshal array: %v (body=%s)", err, rr.Body.String())
	}
	if len(arr) != 3 {
		t.Fatalf("got %d entries, want 3 — body=%s", len(arr), rr.Body.String())
	}
	for i := 1; i < len(arr); i++ {
		if arr[i-1].At >= arr[i].At {
			t.Fatalf("entries not chronological at %d", i)
		}
	}
	if arr[0].Kind != "boot" {
		t.Fatalf("first kind = %q, want boot", arr[0].Kind)
	}
}

// TestSystemUptimeEventsExport_GzipWhenRequested asserts the iter-16 gzip knob
// applies to the uptime export too: Accept-Encoding: gzip compresses the body
// transparently, advertises Content-Encoding/Vary headers, and appends ".gz"
// to the attachment filename. The decoded payload must round-trip as the same
// JSONL the non-gzip path would emit.
func TestSystemUptimeEventsExport_GzipWhenRequested(t *testing.T) {
	dir := t.TempDir()
	store, err := uptime.OpenStoreAt(dir)
	if err != nil {
		t.Fatalf("OpenStoreAt: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	events := []uptime.Event{
		{At: now.Add(-3 * time.Minute), Kind: "boot"},
		{At: now.Add(-2 * time.Minute), Kind: "restart", Reason: "agent restart"},
		{At: now.Add(-1 * time.Minute), Kind: "shutdown", Reason: "signal"},
	}
	for i, ev := range events {
		if err := store.Append(ev); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	h := NewSystemUptimeEventsExportHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/api/system/uptime-events/export", nil)
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
	body := rr.Body.Bytes()
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Fatalf("body does not start with gzip magic: % x", body[:minInt(len(body), 4)])
	}

	gzr, err := gzip.NewReader(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gzr.Close()
	plain, err := io.ReadAll(gzr)
	if err != nil {
		t.Fatalf("read decompressed: %v", err)
	}

	var got []uptimeEventExportEntry
	sc := bufio.NewScanner(strings.NewReader(string(plain)))
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e uptimeEventExportEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("unmarshal line %q: %v", string(line), err)
		}
		got = append(got, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != len(events) {
		t.Fatalf("got %d entries, want %d", len(got), len(events))
	}
	if got[0].Kind != "boot" || got[len(got)-1].Kind != "shutdown" {
		t.Fatalf("decoded kind order = [%s..%s], want [boot..shutdown]", got[0].Kind, got[len(got)-1].Kind)
	}
}
