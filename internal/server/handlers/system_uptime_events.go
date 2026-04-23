package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/sysstat/uptime"
)

// SystemUptimeEventsHandler serves /api/system/uptime-events.
//
// The endpoint complements /api/system/health and the rud1-app diagnostics
// view: when a burst of warnings shows up, the operator can cross-reference
// these events to tell a real sustained issue from a transient
// crash-and-recover. The store is small (≤200 events) so each request scans
// the whole ring in memory — pagination would be overkill.
type SystemUptimeEventsHandler struct {
	store *uptime.Store
}

// NewSystemUptimeEventsHandler wraps an uptime store. A nil store is allowed
// (the handler returns 503 on every call) so the agent can degrade gracefully
// when the on-disk file isn't writable.
func NewSystemUptimeEventsHandler(store *uptime.Store) *SystemUptimeEventsHandler {
	return &SystemUptimeEventsHandler{store: store}
}

// uptimeEventItem is the wire-format row. `at` is unix seconds for
// charting-friendly compatibility with the rest of the system endpoints.
type uptimeEventItem struct {
	At            int64  `json:"at"`
	Kind          string `json:"kind"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
	Reason        string `json:"reason"`
}

// uptimeEventsResponse is the top-level payload. `now` lets clients render
// "X minutes ago" without trusting the local browser clock to match the Pi.
type uptimeEventsResponse struct {
	Events []uptimeEventItem `json:"events"`
	Now    int64             `json:"now"`
	Count  int               `json:"count"`
}

// Events handles GET /api/system/uptime-events.
//
// Query params:
//
//	limit — integer 1..200, default 50. Out-of-range values are clamped
//	         silently rather than 400'd; the caller's chart still renders.
//
// Responses:
//
//	200 — `{events[], now, count}` (events newest-first; possibly empty).
//	503 — when the store isn't wired (disk unavailable at boot).
func (h *SystemUptimeEventsHandler) Events(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "uptime events unavailable")
		return
	}

	limit := parseUptimeLimit(r.URL.Query().Get("limit"))
	rows := h.store.List(limit)

	items := make([]uptimeEventItem, len(rows))
	for i, ev := range rows {
		items[i] = uptimeEventItem{
			At:            ev.At.Unix(),
			Kind:          ev.Kind,
			UptimeSeconds: int64(ev.Uptime.Seconds()),
			Reason:        ev.Reason,
		}
	}

	writeJSON(w, http.StatusOK, uptimeEventsResponse{
		Events: items,
		Now:    time.Now().UTC().Unix(),
		Count:  len(items),
	})
}

// parseUptimeLimit clamps the caller's `limit` query param to [1, 200] and
// falls back to 50 when absent or unparseable. Quietly clamping rather than
// erroring matches the convention used by the percentiles handler — the
// chart still renders something useful even when the URL is fat-fingered.
func parseUptimeLimit(raw string) int {
	const (
		defaultLimit = 50
		minLimit     = 1
		maxLimit     = 200
	)
	if raw == "" {
		return defaultLimit
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return defaultLimit
	}
	if n < minLimit {
		return minLimit
	}
	if n > maxLimit {
		return maxLimit
	}
	return n
}
