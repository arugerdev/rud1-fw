package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/sysstat"
)

// SystemPercentilesHistoryHandler serves /api/percentiles/history.
//
// Unlike /api/system/stats (which returns a single point-in-time snapshot)
// this endpoint returns the full disk-backed sample series so the local
// rud1-app and the rud1-desktop diagnostic viewer can chart multi-hour
// trends even immediately after a Pi reboot.
type SystemPercentilesHistoryHandler struct {
	collector *sysstat.Collector
}

// NewSystemPercentilesHistoryHandler wraps a collector. The caller owns
// collector lifetime; we only read through it.
func NewSystemPercentilesHistoryHandler(collector *sysstat.Collector) *SystemPercentilesHistoryHandler {
	return &SystemPercentilesHistoryHandler{collector: collector}
}

// historyResponseItem is the wire-format row. `at` is unix seconds (matches
// the /api/system/stats `capturedAt` spirit of using a primitive that any
// client can plot without re-parsing RFC3339). `cpuPct` and `loadAvg1` are
// named identically to the `sysstat.Stats` fields so the same renderer
// can be reused for live and historical data.
type historyResponseItem struct {
	At       int64   `json:"at"`
	CPUPct   float64 `json:"cpuPct"`
	LoadAvg1 float64 `json:"loadAvg1"`
}

// historyResponse is the top-level payload. `window` echoes the parsed
// caller input so a mismatched query string is visible client-side.
// `samples` is oldest-first (ready to chart without an extra reverse).
type historyResponse struct {
	WindowSeconds int                   `json:"windowSeconds"`
	Count         int                   `json:"count"`
	Samples       []historyResponseItem `json:"samples"`
}

// History handles GET /api/percentiles/history.
//
// Query params:
//
//	window — "1h", "6h", "24h" (or bare integer seconds). Default 24h,
//	         capped at 24h since that's the on-disk retention.
//
// Responses:
//
//	200 — `{windowSeconds, count, samples[]}` (may be empty on a fresh Pi).
//	503 — when the history store isn't wired (older config or disk unavailable).
//	400 — when window fails to parse.
func (h *SystemPercentilesHistoryHandler) History(w http.ResponseWriter, r *http.Request) {
	store := h.collector.History()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "percentile history unavailable")
		return
	}
	window, err := parseWindow(r.URL.Query().Get("window"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	points := store.History(window)
	items := make([]historyResponseItem, len(points))
	for i, p := range points {
		items[i] = historyResponseItem{
			At:       p.At.Unix(),
			CPUPct:   p.CPUPct,
			LoadAvg1: p.LoadAvg1,
		}
	}
	writeJSON(w, http.StatusOK, historyResponse{
		WindowSeconds: int(window.Seconds()),
		Count:         len(items),
		Samples:       items,
	})
}

// parseWindow turns the `?window=` query into a duration. Accepts the
// common shorthands and plain integers (assumed seconds). Anything
// longer than 24h is capped at 24h — the disk retention ceiling.
func parseWindow(raw string) (time.Duration, error) {
	const maxWindow = 24 * time.Hour
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return maxWindow, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, httpParseErr("invalid window: use e.g. 1h, 6h, 24h")
	}
	if d <= 0 {
		return 0, httpParseErr("window must be positive")
	}
	if d > maxWindow {
		d = maxWindow
	}
	return d, nil
}

// httpParseErr is a tiny adapter so the handler can reuse the same error
// type without importing a separate package just for a string error.
type httpParseErr string

func (e httpParseErr) Error() string { return string(e) }
