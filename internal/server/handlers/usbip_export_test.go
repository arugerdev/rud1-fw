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

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/usb/revlog"
)

// TestRevocationsExport_ChronologicalAndFilename seeds the disk-backed
// revocation log with three entries written newest-to-oldest, calls the
// export handler, and asserts:
//
//  1. the Content-Disposition filename embeds the since/until values,
//  2. the response body is JSONL with entries in chronological (oldest-first)
//     order — the reverse of the List() default — so the file reads as an
//     audit trail.
func TestRevocationsExport_ChronologicalAndFilename(t *testing.T) {
	dir := t.TempDir()
	logger, err := revlog.New(dir, 30)
	if err != nil {
		t.Fatalf("revlog.New: %v", err)
	}
	defer logger.Close()

	// Append entries with strictly increasing `At` timestamps. Since revlog
	// writes append-only within a file, the on-disk order is oldest-first,
	// but List returns newest-first — exactly the case the handler must
	// reverse back.
	base := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	ats := []int64{
		base.Unix(),                          // oldest
		base.Add(1 * time.Minute).Unix(),     // middle
		base.Add(2 * time.Minute).Unix(),     // newest
	}
	for i, at := range ats {
		if err := logger.Append(revlog.Entry{
			BusID:  fmt.Sprintf("1-%d", i+1),
			Reason: "policy",
			At:     at,
		}); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	// Minimal handler setup — no USB/IP daemon, no policy. The export path
	// only touches revLogger + authorization, so an empty Config is fine.
	h := &USBIPHandler{
		full: &config.Config{},
		cfg:  &config.USBConfig{}, // AuthorizedNets empty => all clients ok
	}
	h.SetRevLogger(logger)

	since := base.Add(-1 * time.Minute).Unix()
	until := base.Add(10 * time.Minute).Unix()
	url := fmt.Sprintf("/api/usbip/revocations/export?since=%d&until=%d", since, until)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()

	h.RevocationsExport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}

	// Filename must embed the raw since/until and .jsonl suffix.
	cd := rr.Header().Get("Content-Disposition")
	wantName := fmt.Sprintf(`rud1-revocations-%d-%d.jsonl`, since, until)
	if !strings.Contains(cd, wantName) {
		t.Fatalf("Content-Disposition = %q, want filename %q", cd, wantName)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/x-ndjson" {
		t.Fatalf("Content-Type = %q, want application/x-ndjson", got)
	}

	// Parse the JSONL body and verify chronological (oldest-first) order.
	var got []RevocationEntry
	sc := bufio.NewScanner(strings.NewReader(rr.Body.String()))
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e RevocationEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("unmarshal line %q: %v", string(line), err)
		}
		got = append(got, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != len(ats) {
		t.Fatalf("got %d entries, want %d", len(got), len(ats))
	}
	// Export must be oldest-first — opposite of List's newest-first default.
	for i := 1; i < len(got); i++ {
		if got[i-1].At >= got[i].At {
			t.Fatalf("entries not chronological at %d: %d >= %d", i, got[i-1].At, got[i].At)
		}
	}
	if got[0].At != ats[0] || got[len(got)-1].At != ats[len(ats)-1] {
		t.Fatalf("chronology mismatch: got first=%d last=%d, want first=%d last=%d",
			got[0].At, got[len(got)-1].At, ats[0], ats[len(ats)-1])
	}
}

// TestRevocationsExport_NoLoggerReturns503 asserts the handler reports 503
// with a JSON error body when no disk logger is wired, matching the spec.
func TestRevocationsExport_NoLoggerReturns503(t *testing.T) {
	h := &USBIPHandler{
		full: &config.Config{},
		cfg:  &config.USBConfig{},
	}
	// revLogger deliberately left nil.

	req := httptest.NewRequest(http.MethodGet, "/api/usbip/revocations/export", nil)
	rr := httptest.NewRecorder()
	h.RevocationsExport(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, rr.Body.String())
	}
	if body["error"] != "disk log unavailable" {
		t.Fatalf("error = %q, want %q", body["error"], "disk log unavailable")
	}
}

// TestRevocationsExport_RejectsInvertedWindow ensures a since>=until window
// is rejected with 400 before we even hit the disk — cheap client-bug guard.
func TestRevocationsExport_RejectsInvertedWindow(t *testing.T) {
	dir := t.TempDir()
	logger, err := revlog.New(dir, 30)
	if err != nil {
		t.Fatalf("revlog.New: %v", err)
	}
	defer logger.Close()

	h := &USBIPHandler{full: &config.Config{}, cfg: &config.USBConfig{}}
	h.SetRevLogger(logger)

	req := httptest.NewRequest(http.MethodGet,
		"/api/usbip/revocations/export?since=200&until=100", nil)
	rr := httptest.NewRecorder()
	h.RevocationsExport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 — body=%s", rr.Code, rr.Body.String())
	}
}

// TestRevocationsExport_GzipWhenRequested asserts the iter-16 transparent
// gzip layer: when the client advertises Accept-Encoding: gzip the handler
// compresses the JSONL stream, sets Content-Encoding/Vary, and suffixes the
// attachment filename with ".gz". Decoding the body must reproduce the same
// chronological JSONL the plaintext path emits — compression is payload-
// transparent by design.
func TestRevocationsExport_GzipWhenRequested(t *testing.T) {
	dir := t.TempDir()
	logger, err := revlog.New(dir, 30)
	if err != nil {
		t.Fatalf("revlog.New: %v", err)
	}
	defer logger.Close()

	base := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	ats := []int64{
		base.Unix(),
		base.Add(1 * time.Minute).Unix(),
		base.Add(2 * time.Minute).Unix(),
	}
	for i, at := range ats {
		if err := logger.Append(revlog.Entry{
			BusID:  fmt.Sprintf("1-%d", i+1),
			Reason: "policy",
			At:     at,
		}); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	h := &USBIPHandler{full: &config.Config{}, cfg: &config.USBConfig{}}
	h.SetRevLogger(logger)

	since := base.Add(-1 * time.Minute).Unix()
	until := base.Add(10 * time.Minute).Unix()
	url := fmt.Sprintf("/api/usbip/revocations/export?since=%d&until=%d", since, until)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	h.RevocationsExport(rr, req)

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
	wantName := fmt.Sprintf(`rud1-revocations-%d-%d.jsonl.gz`, since, until)
	if !strings.Contains(cd, wantName) {
		t.Fatalf("Content-Disposition = %q, want filename %q", cd, wantName)
	}

	// Body must start with gzip magic, decode cleanly, and yield the same
	// chronological JSONL entries the plain path produces.
	body := rr.Body.Bytes()
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Fatalf("body does not start with gzip magic")
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

	var got []RevocationEntry
	sc := bufio.NewScanner(strings.NewReader(string(plain)))
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e RevocationEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("unmarshal line %q: %v", string(line), err)
		}
		got = append(got, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != len(ats) {
		t.Fatalf("got %d entries, want %d", len(got), len(ats))
	}
	if got[0].At != ats[0] || got[len(got)-1].At != ats[len(ats)-1] {
		t.Fatalf("chronology mismatch after gzip decode: got first=%d last=%d, want %d/%d",
			got[0].At, got[len(got)-1].At, ats[0], ats[len(ats)-1])
	}
}

// TestRevocationsExport_NoGzipWhenNotRequested locks in backwards-compat:
// without Accept-Encoding the body is plain JSONL and the filename has no
// ".gz" suffix, so existing curl/browser clients see exactly the pre-iter-16
// response bytes.
func TestRevocationsExport_NoGzipWhenNotRequested(t *testing.T) {
	dir := t.TempDir()
	logger, err := revlog.New(dir, 30)
	if err != nil {
		t.Fatalf("revlog.New: %v", err)
	}
	defer logger.Close()

	base := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	if err := logger.Append(revlog.Entry{
		BusID:  "1-1",
		Reason: "policy",
		At:     base.Unix(),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	h := &USBIPHandler{full: &config.Config{}, cfg: &config.USBConfig{}}
	h.SetRevLogger(logger)

	since := base.Add(-1 * time.Minute).Unix()
	until := base.Add(10 * time.Minute).Unix()
	url := fmt.Sprintf("/api/usbip/revocations/export?since=%d&until=%d", since, until)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	// No Accept-Encoding header — must stay plain JSONL.
	rr := httptest.NewRecorder()
	h.RevocationsExport(rr, req)

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
	body := rr.Body.Bytes()
	if len(body) == 0 || body[0] != '{' {
		t.Fatalf("body[0] = %v, want '{' (plain JSONL)", body[0])
	}
}

// TestRevocationsList_GzipWhenRequested asserts the iter-20 extension: the
// paginated list endpoint now honours Accept-Encoding: gzip. Unlike the
// export path the filename stays attachment-free (it's a JSON payload for
// UI consumption, not a download) — only Content-Encoding/Vary should flip.
// Decoding must produce the same shape the uncompressed path emits.
func TestRevocationsList_GzipWhenRequested(t *testing.T) {
	dir := t.TempDir()
	logger, err := revlog.New(dir, 200)
	if err != nil {
		t.Fatalf("revlog.New: %v", err)
	}
	defer logger.Close()

	// Seed a handful of entries so the response is actually worth compressing.
	base := time.Date(2026, 4, 24, 10, 0, 0, 0, time.UTC)
	const count = 50
	for i := 0; i < count; i++ {
		if err := logger.Append(revlog.Entry{
			BusID:       fmt.Sprintf("2-%d", i+1),
			VendorID:    "1d6b",
			ProductID:   "0003",
			Serial:      fmt.Sprintf("ABC-%04d", i),
			VendorName:  "Linux Foundation",
			ProductName: "3.0 root hub",
			Reason:      "policy",
			At:          base.Add(time.Duration(i) * time.Second).Unix(),
		}); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	h := &USBIPHandler{full: &config.Config{}, cfg: &config.USBConfig{}}
	h.SetRevLogger(logger)

	req := httptest.NewRequest(http.MethodGet, "/api/usbip/revocations?limit=50", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	h.RevocationsList(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := rr.Header().Get("Vary"); got != "Accept-Encoding" {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}
	// List responses are NOT attachments — they are JSON for in-page consumption.
	if cd := rr.Header().Get("Content-Disposition"); cd != "" {
		t.Fatalf("Content-Disposition = %q, want empty (not a download)", cd)
	}

	body := rr.Body.Bytes()
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Fatalf("body does not start with gzip magic (got %x)", body[:2])
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
	var decoded struct {
		Items  []RevocationEntry `json:"items"`
		Total  int               `json:"total"`
		Limit  int               `json:"limit"`
		Offset int               `json:"offset"`
	}
	if err := json.Unmarshal(plain, &decoded); err != nil {
		t.Fatalf("unmarshal decompressed body: %v — %s", err, string(plain))
	}
	if decoded.Total != count {
		t.Fatalf("total = %d, want %d", decoded.Total, count)
	}
	if len(decoded.Items) != count {
		t.Fatalf("items = %d, want %d", len(decoded.Items), count)
	}
	if decoded.Limit != 50 || decoded.Offset != 0 {
		t.Fatalf("limit/offset = %d/%d, want 50/0", decoded.Limit, decoded.Offset)
	}
}

// TestRevocationsList_NoGzipWhenNotRequested locks in the no-compression
// path: without Accept-Encoding the response is plain JSON (Content-Type
// application/json, no Content-Encoding, no Vary) so existing admin clients
// see exactly the pre-iter-20 bytes.
func TestRevocationsList_NoGzipWhenNotRequested(t *testing.T) {
	dir := t.TempDir()
	logger, err := revlog.New(dir, 30)
	if err != nil {
		t.Fatalf("revlog.New: %v", err)
	}
	defer logger.Close()

	if err := logger.Append(revlog.Entry{
		BusID:  "3-1",
		Reason: "policy",
		At:     time.Date(2026, 4, 24, 11, 0, 0, 0, time.UTC).Unix(),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	h := &USBIPHandler{full: &config.Config{}, cfg: &config.USBConfig{}}
	h.SetRevLogger(logger)

	req := httptest.NewRequest(http.MethodGet, "/api/usbip/revocations", nil)
	// No Accept-Encoding header — must stay plain JSON.
	rr := httptest.NewRecorder()
	h.RevocationsList(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	body := rr.Body.Bytes()
	if len(body) == 0 || body[0] != '{' {
		t.Fatalf("body[0] = %v, want '{' (plain JSON)", body[0])
	}
}
