package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/sysstat"
)

// SystemPercentilesExportHandler serves /api/percentiles/export.
//
// Mirrors the audit-style download pattern used by /api/usbip/revocations/export
// (see usbip.go RevocationsExport): operators get a single attachment they can
// keep alongside an incident report instead of re-running the live history
// endpoint and praying the rolling window still covers the moment of interest.
//
// The handler only reads from the collector's HistoryStore — it never mutates
// state — so a single instance is safe to share across requests.
type SystemPercentilesExportHandler struct {
	collector *sysstat.Collector
}

// NewSystemPercentilesExportHandler wraps a collector. The caller owns the
// collector lifetime; we only read through it.
func NewSystemPercentilesExportHandler(collector *sysstat.Collector) *SystemPercentilesExportHandler {
	return &SystemPercentilesExportHandler{collector: collector}
}

// percentilesExportEntry is the wire-format row. Field names mirror
// historyResponseItem in system_percentiles_history.go so the same
// downstream renderer can consume both endpoints without a translation
// layer.
type percentilesExportEntry struct {
	At       int64   `json:"at"`
	CPUPct   float64 `json:"cpuPct"`
	LoadAvg1 float64 `json:"loadAvg1"`
}

// pctExportMaxWindow caps the requested window at 24h to match the on-disk
// retention ceiling enforced by /api/percentiles/history. Anything broader
// would silently truncate, so we'd rather narrow the request up-front than
// hand the operator a file that quietly omits older samples.
const pctExportMaxWindow = 24 * time.Hour

// Export handles GET /api/percentiles/export.
//
// Query params (all optional):
//
//	since  — unix seconds, default = now - 24h
//	until  — unix seconds, default = now
//	format — "jsonl" (default, application/x-ndjson) or "json" (JSON array)
//
// Responses:
//
//	200 — streamed attachment; one line per sample (jsonl) or single array (json).
//	400 — malformed / inverted window or unknown format.
//	503 — collector has no HistoryStore wired (older config / disk unavailable).
//
// The implementation streams via bufio.Writer and flushes per entry so peak
// memory stays flat regardless of window size — same shape as RevocationsExport.
func (h *SystemPercentilesExportHandler) Export(w http.ResponseWriter, r *http.Request) {
	store := h.collector.History()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "history unavailable")
		return
	}

	now := time.Now()
	since, until, err := parseExportWindow(r.URL.Query(), now)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Apply defaults: a missing since means "the last 24h", a missing until
	// means "right now". We keep the raw values for the filename so the
	// operator can tell at a glance which call produced which file.
	effSince := since
	if effSince == 0 {
		effSince = now.Add(-pctExportMaxWindow).Unix()
	}
	effUntil := until
	if effUntil == 0 {
		effUntil = now.Unix()
	}
	if effSince >= effUntil {
		writeError(w, http.StatusBadRequest, "until must be greater than since")
		return
	}

	// Format selection: matches RevocationsExport so a typo doesn't silently
	// fall back to an unexpected shape.
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "jsonl"
	}
	if format != "jsonl" && format != "json" {
		writeError(w, http.StatusBadRequest, "format must be jsonl or json")
		return
	}

	// HistoryStore.History takes a window duration, not since/until. Compute
	// the window relative to now so we cover everything from `effSince`
	// forward, then filter the upper bound in-memory below. Cap at 24h to
	// match the disk retention.
	window := now.Sub(time.Unix(effSince, 0))
	if window <= 0 {
		// Defensive: effSince was in the future. Treat as empty window.
		window = time.Second
	}
	if window > pctExportMaxWindow {
		window = pctExportMaxWindow
	}
	points := store.History(window)

	// In-memory upper-bound filter: drop anything strictly after `effUntil`.
	// History is oldest-first, so once we hit a point past the bound every
	// subsequent point is also out — but the slice is small (≤ a few thousand
	// rows for 24h at 1/min) so the simple linear filter is plenty.
	filtered := points[:0]
	for _, p := range points {
		if p.At.Unix() > effUntil {
			continue
		}
		if p.At.Unix() < effSince {
			continue
		}
		filtered = append(filtered, p)
	}

	// Headers MUST be set before any byte of the body. Filename embeds the
	// raw since/until (defaults applied) so two downloads in the same folder
	// don't collide.
	ext := format
	filename := fmt.Sprintf("rud1-percentiles-%d-%d.%s", effSince, effUntil, ext)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
	}
	w.WriteHeader(http.StatusOK)

	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)

	if format == "json" {
		// Stream as a JSON array: hand-rolled brackets/commas so we can
		// flush per element and keep peak memory bounded.
		if _, err := bw.WriteString("["); err != nil {
			log.Warn().Err(err).Msg("percentiles: export write failed")
			return
		}
		for i, p := range filtered {
			if i > 0 {
				if _, err := bw.WriteString(","); err != nil {
					log.Warn().Err(err).Msg("percentiles: export write failed")
					return
				}
			}
			if err := enc.Encode(percentilesExportEntry{
				At:       p.At.Unix(),
				CPUPct:   p.CPUPct,
				LoadAvg1: p.LoadAvg1,
			}); err != nil {
				log.Warn().Err(err).Msg("percentiles: export encode failed")
				return
			}
			if err := bw.Flush(); err != nil {
				log.Warn().Err(err).Msg("percentiles: export flush failed")
				return
			}
		}
		if _, err := bw.WriteString("]\n"); err != nil {
			log.Warn().Err(err).Msg("percentiles: export write failed")
			return
		}
		_ = bw.Flush()
		return
	}

	// jsonl: one JSON object per line; flush per entry so memory stays flat
	// even for multi-thousand-entry exports.
	for _, p := range filtered {
		if err := enc.Encode(percentilesExportEntry{
			At:       p.At.Unix(),
			CPUPct:   p.CPUPct,
			LoadAvg1: p.LoadAvg1,
		}); err != nil {
			log.Warn().Err(err).Msg("percentiles: export encode failed")
			return
		}
		if err := bw.Flush(); err != nil {
			log.Warn().Err(err).Msg("percentiles: export flush failed")
			return
		}
	}
}
