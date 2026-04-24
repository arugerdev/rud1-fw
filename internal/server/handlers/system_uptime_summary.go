package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/sysstat/uptime"
)

// SystemUptimeSummaryHandler serves /api/system/uptime-summary.
//
// The endpoint precomputes the aggregates rud1-app would otherwise reduce
// client-side from /api/system/uptime-events: boot/restart/shutdown counts,
// a "clean shutdown" ratio (how many boot-like events were preceded by a
// matching shutdown), mean uptime across the window, and the per-kind
// last-seen timestamps. Returning them server-side keeps mobile/low-power
// dashboards cheap — the window caller asked for is the window they get
// back, no scan-all-the-events round-trip.
type SystemUptimeSummaryHandler struct {
	store *uptime.Store
}

// NewSystemUptimeSummaryHandler wraps an uptime store. A nil store is
// allowed (the handler returns 503) so the agent can degrade gracefully
// when the on-disk file isn't writable.
func NewSystemUptimeSummaryHandler(store *uptime.Store) *SystemUptimeSummaryHandler {
	return &SystemUptimeSummaryHandler{store: store}
}

// uptimeSummaryResponse is the wire-format payload.
//
// Nullable fields use `*int64` / `*float64` so JSON encoding emits `null`
// instead of a misleading `0` when the underlying quantity is undefined
// (e.g. no boot events in window → lastBootAt must be null, not 0).
type uptimeSummaryResponse struct {
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

// Summary window bounds. 1h floor matches the practical minimum for a
// useful "last X" dashboard tile; 30d ceiling lines up with the other
// history endpoints' longest plausible retention. The store only holds
// 200 events so a wider window doesn't surface any extra rows, but
// clamping quietly (rather than erroring) matches the `parseWindow`
// convention used elsewhere — the dashboard still renders something
// useful even when the URL is fat-fingered.
const (
	uptimeSummaryDefaultWindow = 24 * time.Hour
	uptimeSummaryMinWindow     = 1 * time.Hour
	uptimeSummaryMaxWindow     = 30 * 24 * time.Hour
)

// Summary handles GET /api/system/uptime-summary.
//
// Query params:
//
//	window — Go duration (e.g. 1h, 6h, 24h, 168h). Default 24h.
//	          Clamped quietly to [1h, 720h].
//
// Responses:
//
//	200 — `{windowSeconds, now, bootCount, restartCount, shutdownCount,
//	        cleanShutdownRatio, meanUptimeSeconds, lastBootAt,
//	        lastShutdownAt, lastRestartAt}`.
//	503 — store isn't wired (disk unavailable at boot).
func (h *SystemUptimeSummaryHandler) Summary(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "uptime events unavailable")
		return
	}

	window := parseUptimeSummaryWindow(r.URL.Query().Get("window"))
	now := time.Now().UTC()
	cutoff := now.Add(-window)

	// Filter the ring to the window. The store caps at 200 events so
	// scanning the whole thing in memory is cheap — no need for a
	// sorted-index lookup.
	events := h.store.List(0)
	var (
		bootCount, restartCount, shutdownCount int
		uptimeSum                              time.Duration
		uptimeSamples                          int
		lastBoot, lastShutdown, lastRestart    *int64
	)
	for _, ev := range events {
		if !ev.At.After(cutoff) {
			continue
		}
		at := ev.At.Unix()
		switch ev.Kind {
		case "boot":
			bootCount++
			if lastBoot == nil || at > *lastBoot {
				v := at
				lastBoot = &v
			}
		case "restart":
			restartCount++
			if lastRestart == nil || at > *lastRestart {
				v := at
				lastRestart = &v
			}
		case "shutdown":
			shutdownCount++
			if lastShutdown == nil || at > *lastShutdown {
				v := at
				lastShutdown = &v
			}
		}
		if ev.Uptime > 0 {
			uptimeSum += ev.Uptime
			uptimeSamples++
		}
	}

	// cleanShutdownRatio = shutdowns / (boots + restarts). Denominator zero
	// ⇒ null (rather than 0 or NaN) so the dashboard can render "—" rather
	// than a misleading "0% clean".
	var ratio *float64
	if denom := bootCount + restartCount; denom > 0 {
		v := float64(shutdownCount) / float64(denom)
		ratio = &v
	}

	// meanUptimeSeconds across events that carried an Uptime > 0. Null
	// when no event in the window reported one (same rationale as ratio).
	var meanUptime *int64
	if uptimeSamples > 0 {
		v := int64(uptimeSum.Seconds()) / int64(uptimeSamples)
		meanUptime = &v
	}

	writeJSON(w, http.StatusOK, uptimeSummaryResponse{
		WindowSeconds:      int64(window.Seconds()),
		Now:                now.Unix(),
		BootCount:          bootCount,
		RestartCount:       restartCount,
		ShutdownCount:      shutdownCount,
		CleanShutdownRatio: ratio,
		MeanUptimeSeconds:  meanUptime,
		LastBootAt:         lastBoot,
		LastShutdownAt:     lastShutdown,
		LastRestartAt:      lastRestart,
	})
}

// parseUptimeSummaryWindow turns the `?window=` query into a duration,
// quietly clamping to [1h, 30d]. Defaults to 24h on empty / unparseable
// input — same policy as parseUptimeLimit: the dashboard still renders
// something useful even when the URL is fat-fingered. Kept as a
// dedicated helper rather than reusing the percentiles `parseWindow`
// because that one caps at 24h (tied to the percentiles retention
// ceiling) and rejects non-positive values with an error — neither is
// the right behaviour here.
func parseUptimeSummaryWindow(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return uptimeSummaryDefaultWindow
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return uptimeSummaryDefaultWindow
	}
	if d < uptimeSummaryMinWindow {
		return uptimeSummaryMinWindow
	}
	if d > uptimeSummaryMaxWindow {
		return uptimeSummaryMaxWindow
	}
	return d
}
