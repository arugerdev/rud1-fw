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
