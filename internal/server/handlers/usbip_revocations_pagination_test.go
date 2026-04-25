package handlers

import (
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

// revocationsListResponse mirrors the iter-36 wrapper shape returned by
// RevocationsList. Fields are pointers/zero-default so a missing key is
// distinguishable from a zero value during decoding.
type revocationsListResponse struct {
	Items    []RevocationEntry `json:"items"`
	Total    int               `json:"total"`
	Limit    int               `json:"limit"`
	Offset   int               `json:"offset"`
	Returned int               `json:"returned"`
	HasMore  bool              `json:"hasMore"`
}

// seedRingBufferRevocations records `count` policy revocations with strictly
// increasing `At` timestamps (1 second apart starting at `base`). The newest
// entry will be at base + (count-1) seconds.
func seedRingBufferRevocations(t *testing.T, h *USBIPHandler, count int, base time.Time) {
	t.Helper()
	for i := 0; i < count; i++ {
		h.recordRevocation(RevocationEntry{
			BusID:  fmt.Sprintf("1-%d", i+1),
			Reason: RevocationReasonPolicy,
			At:     base.Add(time.Duration(i) * time.Second).Unix(),
		})
	}
}

// decodeRevList runs the handler against the given URL and decodes the JSON
// wrapper, asserting a 200 status. Returns the decoded payload so the caller
// can assert specific fields without repeating boilerplate per test case.
func decodeRevList(t *testing.T, h *USBIPHandler, url string) revocationsListResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	h.RevocationsList(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	var resp revocationsListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal body: %v — %s", err, rr.Body.String())
	}
	return resp
}

// TestRevocationsList_DefaultPreservesAllInRing asserts the no-query-param
// shape: when no limit is supplied the handler returns the entire ring buffer
// (newest-first) and reports total/returned/hasMore consistently. This locks
// in the "default = return everything" contract that pre-iter-36 callers
// rely on.
func TestRevocationsList_DefaultPreservesAllInRing(t *testing.T) {
	h := &USBIPHandler{full: &config.Config{}, cfg: &config.USBConfig{}}
	base := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	seedRingBufferRevocations(t, h, 10, base)

	resp := decodeRevList(t, h, "/api/usbip/revocations")

	if resp.Total != 10 {
		t.Fatalf("total = %d, want 10", resp.Total)
	}
	if len(resp.Items) != 10 {
		t.Fatalf("len(items) = %d, want 10", len(resp.Items))
	}
	if resp.Returned != 10 {
		t.Fatalf("returned = %d, want 10", resp.Returned)
	}
	if resp.HasMore {
		t.Fatalf("hasMore = true, want false (returned everything)")
	}
	// Newest-first: items[0].At must be the largest seeded timestamp.
	wantNewest := base.Add(9 * time.Second).Unix()
	if resp.Items[0].At != wantNewest {
		t.Fatalf("items[0].At = %d, want %d (newest-first)", resp.Items[0].At, wantNewest)
	}
}

// TestRevocationsList_LimitOne asserts that `?limit=1` returns exactly one
// row — the newest — and reports hasMore=true so the client knows another
// page exists. The default offset of 0 is implicit.
func TestRevocationsList_LimitOne(t *testing.T) {
	h := &USBIPHandler{full: &config.Config{}, cfg: &config.USBConfig{}}
	base := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	seedRingBufferRevocations(t, h, 5, base)

	resp := decodeRevList(t, h, "/api/usbip/revocations?limit=1")

	if resp.Limit != 1 {
		t.Fatalf("limit = %d, want 1", resp.Limit)
	}
	if resp.Returned != 1 {
		t.Fatalf("returned = %d, want 1", resp.Returned)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(resp.Items))
	}
	if !resp.HasMore {
		t.Fatalf("hasMore = false, want true (4 entries past the page)")
	}
	wantNewest := base.Add(4 * time.Second).Unix()
	if resp.Items[0].At != wantNewest {
		t.Fatalf("items[0].At = %d, want %d (newest)", resp.Items[0].At, wantNewest)
	}
}

// TestRevocationsList_LimitCapToRingSize fills the ring to capacity and asks
// for exactly revocationLogSize entries, asserting the cap is honoured (the
// page is full, total equals ring size, hasMore=false).
func TestRevocationsList_LimitCapToRingSize(t *testing.T) {
	h := &USBIPHandler{full: &config.Config{}, cfg: &config.USBConfig{}}
	base := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	seedRingBufferRevocations(t, h, revocationLogSize, base)

	url := fmt.Sprintf("/api/usbip/revocations?limit=%d", revocationLogSize)
	resp := decodeRevList(t, h, url)

	if resp.Total != revocationLogSize {
		t.Fatalf("total = %d, want %d", resp.Total, revocationLogSize)
	}
	if resp.Returned != revocationLogSize {
		t.Fatalf("returned = %d, want %d", resp.Returned, revocationLogSize)
	}
	if resp.HasMore {
		t.Fatalf("hasMore = true, want false (asked for the whole ring)")
	}
}

// TestRevocationsList_InvalidLimit covers every 400-able shape the parser
// should reject. Each row exercises a distinct branch (non-int, zero,
// negative, above max). Validation errors must NOT touch the body decoder
// — the handler short-circuits with writeError.
func TestRevocationsList_InvalidLimit(t *testing.T) {
	h := &USBIPHandler{full: &config.Config{}, cfg: &config.USBConfig{}}
	base := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	seedRingBufferRevocations(t, h, 5, base)

	cases := []struct {
		name string
		raw  string
	}{
		{"non-integer", "abc"},
		{"zero", "0"},
		{"negative", "-1"},
		{"above-max", fmt.Sprintf("%d", revocationLogSize+1)},
		{"empty-then-junk", "1.5"}, // strconv.Atoi rejects floats
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := "/api/usbip/revocations?limit=" + tc.raw
			req := httptest.NewRequest(http.MethodGet, url, nil)
			rr := httptest.NewRecorder()
			h.RevocationsList(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 — body=%s", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "limit") {
				t.Fatalf("error body does not mention 'limit': %s", rr.Body.String())
			}
		})
	}
}

// TestRevocationsList_InvalidSince asserts the new `since` query param
// rejects malformed and negative values. RFC3339 strings must 400 since the
// firmware contract is unix-seconds (matches the export endpoint and what
// rud1-app's fetchUsbipRevocations sends).
func TestRevocationsList_InvalidSince(t *testing.T) {
	h := &USBIPHandler{full: &config.Config{}, cfg: &config.USBConfig{}}
	cases := []string{"notanint", "-5", "2026-04-25T10:00:00Z"}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			url := "/api/usbip/revocations?since=" + raw
			req := httptest.NewRequest(http.MethodGet, url, nil)
			rr := httptest.NewRecorder()
			h.RevocationsList(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 — body=%s", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "since") {
				t.Fatalf("error body does not mention 'since': %s", rr.Body.String())
			}
		})
	}
}

// TestRevocationsList_LimitWithSince exercises the combined filter — `since`
// is applied first, then the latest N from the post-filter set are returned.
// We seed 10 entries 1s apart, ask for since=base+5 (keeps entries 5..9 → 5
// rows) with limit=2, and assert we get the two newest within the window
// (entries 9 and 8) plus total=5 + hasMore=true.
func TestRevocationsList_LimitWithSince(t *testing.T) {
	h := &USBIPHandler{full: &config.Config{}, cfg: &config.USBConfig{}}
	base := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	seedRingBufferRevocations(t, h, 10, base)

	since := base.Add(5 * time.Second).Unix()
	url := fmt.Sprintf("/api/usbip/revocations?since=%d&limit=2", since)
	resp := decodeRevList(t, h, url)

	if resp.Total != 5 {
		t.Fatalf("total = %d, want 5 (entries 5..9 pass the since filter)", resp.Total)
	}
	if resp.Returned != 2 {
		t.Fatalf("returned = %d, want 2", resp.Returned)
	}
	if !resp.HasMore {
		t.Fatalf("hasMore = false, want true (3 more past the page)")
	}
	// Newest-first: items[0] = entry 9, items[1] = entry 8.
	if got, want := resp.Items[0].At, base.Add(9*time.Second).Unix(); got != want {
		t.Fatalf("items[0].At = %d, want %d", got, want)
	}
	if got, want := resp.Items[1].At, base.Add(8*time.Second).Unix(); got != want {
		t.Fatalf("items[1].At = %d, want %d", got, want)
	}
}

// TestRevocationsList_DiskBackedLimitWithSince mirrors the in-memory
// combined-filter test against the disk-backed path so the two code branches
// stay in lockstep. The disk logger's ListOptions natively supports Since,
// so the only thing the handler does is plumb it through; this test catches
// any future regression where the wiring is dropped.
func TestRevocationsList_DiskBackedLimitWithSince(t *testing.T) {
	dir := t.TempDir()
	logger, err := revlog.New(dir, 30)
	if err != nil {
		t.Fatalf("revlog.New: %v", err)
	}
	defer logger.Close()

	base := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		if err := logger.Append(revlog.Entry{
			BusID:  fmt.Sprintf("2-%d", i+1),
			Reason: "policy",
			At:     base.Add(time.Duration(i) * time.Second).Unix(),
		}); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	h := &USBIPHandler{full: &config.Config{}, cfg: &config.USBConfig{}}
	h.SetRevLogger(logger)

	since := base.Add(5 * time.Second).Unix()
	url := fmt.Sprintf("/api/usbip/revocations?since=%d&limit=2", since)
	resp := decodeRevList(t, h, url)

	if resp.Total != 5 {
		t.Fatalf("total = %d, want 5", resp.Total)
	}
	if resp.Returned != 2 {
		t.Fatalf("returned = %d, want 2", resp.Returned)
	}
	if !resp.HasMore {
		t.Fatalf("hasMore = false, want true")
	}
}

// TestRevocationsList_DiskBackedLimitAboveMaxRejected guards the
// disk-logger-specific cap (revocationListMaxLimit). The in-memory path
// caps at revocationLogSize (256); with a disk logger wired the limit can
// go up to 1000, but anything beyond must still 400.
func TestRevocationsList_DiskBackedLimitAboveMaxRejected(t *testing.T) {
	dir := t.TempDir()
	logger, err := revlog.New(dir, 30)
	if err != nil {
		t.Fatalf("revlog.New: %v", err)
	}
	defer logger.Close()

	h := &USBIPHandler{full: &config.Config{}, cfg: &config.USBConfig{}}
	h.SetRevLogger(logger)

	url := fmt.Sprintf("/api/usbip/revocations?limit=%d", revocationListMaxLimit+1)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	h.RevocationsList(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), fmt.Sprintf("[1,%d]", revocationListMaxLimit)) {
		t.Fatalf("error body should mention max %d: %s", revocationListMaxLimit, rr.Body.String())
	}
}
