package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/sysstat/uptime"
)

// summaryDecoded mirrors the wire shape but binds nullable fields to
// pointers so tests can distinguish "missing" from "zero".
type summaryDecoded struct {
	WindowSeconds      int64    `json:"windowSeconds"`
	Now                int64    `json:"now"`
	BootCount          int      `json:"bootCount"`
	RestartCount       int      `json:"restartCount"`
	ShutdownCount      int      `json:"shutdownCount"`
	CleanShutdownRatio *float64 `json:"cleanShutdownRatio"`
	MeanUptimeSeconds  *int64   `json:"meanUptimeSeconds"`
	LastBootAt         *int64   `json:"lastBootAt"`
	LastShutdownAt     *int64   `json:"lastShutdownAt"`
	LastRestartAt      *int64   `json:"lastRestartAt"`
}

func decodeSummary(t *testing.T, body []byte) summaryDecoded {
	t.Helper()
	var got summaryDecoded
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, string(body))
	}
	return got
}

// TestSystemUptimeSummary_NoStoreReturns503 asserts the handler reports
// 503 with `{error: "uptime events unavailable"}` when the store is nil,
// matching the live /api/system/uptime-events and export behaviour.
func TestSystemUptimeSummary_NoStoreReturns503(t *testing.T) {
	h := NewSystemUptimeSummaryHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/system/uptime-summary", nil)
	rr := httptest.NewRecorder()
	h.Summary(rr, req)

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

// TestSystemUptimeSummary_EmptyStoreReturnsZeros asserts a store with no
// events returns zero counts, nil `last*` fields, and a nil ratio
// (denominator would be 0).
func TestSystemUptimeSummary_EmptyStoreReturnsZeros(t *testing.T) {
	dir := t.TempDir()
	store, err := uptime.OpenStoreAt(dir)
	if err != nil {
		t.Fatalf("OpenStoreAt: %v", err)
	}

	h := NewSystemUptimeSummaryHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/api/system/uptime-summary", nil)
	rr := httptest.NewRecorder()
	h.Summary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	got := decodeSummary(t, rr.Body.Bytes())
	if got.BootCount != 0 || got.RestartCount != 0 || got.ShutdownCount != 0 {
		t.Fatalf("counts = {%d,%d,%d}, want all 0", got.BootCount, got.RestartCount, got.ShutdownCount)
	}
	if got.CleanShutdownRatio != nil {
		t.Fatalf("cleanShutdownRatio = %v, want null", *got.CleanShutdownRatio)
	}
	if got.MeanUptimeSeconds != nil {
		t.Fatalf("meanUptimeSeconds = %v, want null", *got.MeanUptimeSeconds)
	}
	if got.LastBootAt != nil || got.LastShutdownAt != nil || got.LastRestartAt != nil {
		t.Fatalf("last*At = {%v,%v,%v}, want all null", got.LastBootAt, got.LastShutdownAt, got.LastRestartAt)
	}
	if got.WindowSeconds != int64((24 * time.Hour).Seconds()) {
		t.Fatalf("windowSeconds = %d, want %d", got.WindowSeconds, int64((24 * time.Hour).Seconds()))
	}
	if got.Now <= 0 {
		t.Fatalf("now = %d, want > 0", got.Now)
	}
}

// TestSystemUptimeSummary_ComputesAggregatesCorrectly seeds 3 boots + 2
// restarts + 2 shutdowns with varied uptime values and asserts every
// numeric field lines up with the hand-computed aggregate.
//
// Ratio math: shutdownCount / (bootCount + restartCount) = 2/5 = 0.4.
// Uptime samples (events with Uptime > 0): boots 2+3 have 10s, 30s;
// restarts both have 60s, 120s; shutdowns have 300s, 600s ⇒ mean =
// (10+30+60+120+300+600)/6 = 1120/6 = 186 (integer truncation matching
// the handler's int64 math).
func TestSystemUptimeSummary_ComputesAggregatesCorrectly(t *testing.T) {
	dir := t.TempDir()
	store, err := uptime.OpenStoreAt(dir)
	if err != nil {
		t.Fatalf("OpenStoreAt: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	// All within the default 24h window. Oldest first so Append order
	// mirrors real-world chronology; the handler filters by `At.After`,
	// not by append index.
	events := []uptime.Event{
		{At: now.Add(-6 * time.Hour), Kind: "boot", Uptime: 0}, // first boot: no prior uptime
		{At: now.Add(-5 * time.Hour), Kind: "shutdown", Uptime: 300 * time.Second},
		{At: now.Add(-4 * time.Hour), Kind: "boot", Uptime: 10 * time.Second},
		{At: now.Add(-3 * time.Hour), Kind: "restart", Uptime: 60 * time.Second},
		{At: now.Add(-2*time.Hour - 30*time.Minute), Kind: "shutdown", Uptime: 600 * time.Second},
		{At: now.Add(-2 * time.Hour), Kind: "boot", Uptime: 30 * time.Second},
		{At: now.Add(-1 * time.Hour), Kind: "restart", Uptime: 120 * time.Second},
	}
	for i, ev := range events {
		if err := store.Append(ev); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	h := NewSystemUptimeSummaryHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/api/system/uptime-summary", nil)
	rr := httptest.NewRecorder()
	h.Summary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	got := decodeSummary(t, rr.Body.Bytes())

	if got.BootCount != 3 {
		t.Fatalf("bootCount = %d, want 3", got.BootCount)
	}
	if got.RestartCount != 2 {
		t.Fatalf("restartCount = %d, want 2", got.RestartCount)
	}
	if got.ShutdownCount != 2 {
		t.Fatalf("shutdownCount = %d, want 2", got.ShutdownCount)
	}

	if got.CleanShutdownRatio == nil {
		t.Fatalf("cleanShutdownRatio = nil, want 0.4")
	}
	if *got.CleanShutdownRatio != 0.4 {
		t.Fatalf("cleanShutdownRatio = %v, want 0.4", *got.CleanShutdownRatio)
	}

	// (10+30+60+120+300+600)/6 = 186.
	if got.MeanUptimeSeconds == nil {
		t.Fatalf("meanUptimeSeconds = nil, want 186")
	}
	if *got.MeanUptimeSeconds != 186 {
		t.Fatalf("meanUptimeSeconds = %d, want 186", *got.MeanUptimeSeconds)
	}

	// Most-recent timestamps per kind.
	wantLastBoot := now.Add(-2 * time.Hour).Unix()
	wantLastRestart := now.Add(-1 * time.Hour).Unix()
	wantLastShutdown := now.Add(-2*time.Hour - 30*time.Minute).Unix()

	if got.LastBootAt == nil || *got.LastBootAt != wantLastBoot {
		t.Fatalf("lastBootAt = %v, want %d", got.LastBootAt, wantLastBoot)
	}
	if got.LastRestartAt == nil || *got.LastRestartAt != wantLastRestart {
		t.Fatalf("lastRestartAt = %v, want %d", got.LastRestartAt, wantLastRestart)
	}
	if got.LastShutdownAt == nil || *got.LastShutdownAt != wantLastShutdown {
		t.Fatalf("lastShutdownAt = %v, want %d", got.LastShutdownAt, wantLastShutdown)
	}
}

// TestSystemUptimeSummary_WindowClampsMin1h asserts `window=5m` clamps
// quietly up to the 1h floor rather than 400-ing, matching the
// parseWindow/parseUptimeLimit convention.
func TestSystemUptimeSummary_WindowClampsMin1h(t *testing.T) {
	dir := t.TempDir()
	store, err := uptime.OpenStoreAt(dir)
	if err != nil {
		t.Fatalf("OpenStoreAt: %v", err)
	}
	h := NewSystemUptimeSummaryHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/api/system/uptime-summary?window=5m", nil)
	rr := httptest.NewRecorder()
	h.Summary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	got := decodeSummary(t, rr.Body.Bytes())
	if got.WindowSeconds != 3600 {
		t.Fatalf("windowSeconds = %d, want 3600", got.WindowSeconds)
	}
}

// TestSystemUptimeSummary_WindowClampsMax30d covers both the "inside the
// band" case (48h passes through verbatim) and the ceiling clamp
// (2000h → 720h). Both in one test so the tabular expectations keep the
// band's upper edge next to a value just below it.
func TestSystemUptimeSummary_WindowClampsMax30d(t *testing.T) {
	dir := t.TempDir()
	store, err := uptime.OpenStoreAt(dir)
	if err != nil {
		t.Fatalf("OpenStoreAt: %v", err)
	}
	h := NewSystemUptimeSummaryHandler(store)

	cases := []struct {
		query          string
		wantWindowSecs int64
	}{
		{"window=48h", int64((48 * time.Hour).Seconds())},
		{"window=2000h", int64((720 * time.Hour).Seconds())},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/system/uptime-summary?"+tc.query, nil)
			rr := httptest.NewRecorder()
			h.Summary(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
			}
			got := decodeSummary(t, rr.Body.Bytes())
			if got.WindowSeconds != tc.wantWindowSecs {
				t.Fatalf("windowSeconds = %d, want %d", got.WindowSeconds, tc.wantWindowSecs)
			}
		})
	}
}

// TestSystemUptimeSummary_WindowFiltersOlder seeds one event inside the
// window plus one event well outside it and asserts the outside one is
// excluded from every count and `last*` timestamp.
func TestSystemUptimeSummary_WindowFiltersOlder(t *testing.T) {
	dir := t.TempDir()
	store, err := uptime.OpenStoreAt(dir)
	if err != nil {
		t.Fatalf("OpenStoreAt: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	// Ancient events — 48h ago falls well outside the requested 1h
	// window. Fresh event — 30min ago — is inside the 1h window.
	if err := store.Append(uptime.Event{At: now.Add(-48 * time.Hour), Kind: "boot", Uptime: 100 * time.Second}); err != nil {
		t.Fatalf("Append ancient boot: %v", err)
	}
	if err := store.Append(uptime.Event{At: now.Add(-47 * time.Hour), Kind: "shutdown", Uptime: 3600 * time.Second}); err != nil {
		t.Fatalf("Append ancient shutdown: %v", err)
	}
	if err := store.Append(uptime.Event{At: now.Add(-30 * time.Minute), Kind: "restart", Uptime: 42 * time.Second}); err != nil {
		t.Fatalf("Append fresh restart: %v", err)
	}

	h := NewSystemUptimeSummaryHandler(store)
	// Request a 1h window explicitly — ancient events are 48h old so
	// they MUST be filtered out entirely.
	req := httptest.NewRequest(http.MethodGet, "/api/system/uptime-summary?window=1h", nil)
	rr := httptest.NewRecorder()
	h.Summary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body=%s", rr.Code, rr.Body.String())
	}
	got := decodeSummary(t, rr.Body.Bytes())

	if got.BootCount != 0 {
		t.Fatalf("bootCount = %d, want 0 (ancient boot should be filtered)", got.BootCount)
	}
	if got.ShutdownCount != 0 {
		t.Fatalf("shutdownCount = %d, want 0 (ancient shutdown should be filtered)", got.ShutdownCount)
	}
	if got.RestartCount != 1 {
		t.Fatalf("restartCount = %d, want 1 (fresh restart should be included)", got.RestartCount)
	}
	if got.LastBootAt != nil {
		t.Fatalf("lastBootAt = %v, want nil", *got.LastBootAt)
	}
	if got.LastShutdownAt != nil {
		t.Fatalf("lastShutdownAt = %v, want nil", *got.LastShutdownAt)
	}
	if got.LastRestartAt == nil {
		t.Fatalf("lastRestartAt = nil, want %d", now.Add(-30*time.Minute).Unix())
	}
	// Mean uptime draws only from the restart's 42s sample — the
	// ancient entries are filtered before the Uptime accumulator runs.
	if got.MeanUptimeSeconds == nil || *got.MeanUptimeSeconds != 42 {
		t.Fatalf("meanUptimeSeconds = %v, want 42", got.MeanUptimeSeconds)
	}
	// Ratio: shutdowns=0, boots=0, restarts=1 ⇒ 0/1 = 0.0 (NOT nil —
	// denominator is non-zero).
	if got.CleanShutdownRatio == nil {
		t.Fatalf("cleanShutdownRatio = nil, want 0.0 (denominator=1)")
	}
	if *got.CleanShutdownRatio != 0.0 {
		t.Fatalf("cleanShutdownRatio = %v, want 0.0", *got.CleanShutdownRatio)
	}
}
