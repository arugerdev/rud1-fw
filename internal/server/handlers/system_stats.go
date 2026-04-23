package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/sysstat"
)

// SystemStatsHandler serves the /api/system/stats endpoint.
//
// This is intentionally separate from SystemHandler/Info: `Info` returns
// slow-changing identity + feature state (VPN, network, registration) for
// the rud1-app dashboard landing page, while `/api/system/stats` returns
// only the fast-moving host metrics consumed by the live resources widget
// and by the cloud's heartbeat for device health graphs.
type SystemStatsHandler struct {
	collector *sysstat.Collector
}

// NewSystemStatsHandler wraps a collector. The caller owns the collector
// lifetime (there isn't any per-request state to release).
func NewSystemStatsHandler(collector *sysstat.Collector) *SystemStatsHandler {
	return &SystemStatsHandler{collector: collector}
}

// Stats handles GET /api/system/stats.
//
// Supports an optional `?percentiles=1` (or any non-empty value) query
// parameter: when present the response includes a `percentiles` field
// with rolling p50/p95 over the last hour for CPU% and LoadAvg1. The
// field is absent when not requested so pre-existing clients see the
// identical payload shape they always have.
func (h *SystemStatsHandler) Stats(w http.ResponseWriter, r *http.Request) {
	// 2s is plenty: the CPU sample is ~250ms, the rest are /proc reads.
	// If we exceed it the handler degrades gracefully (CPUUsage → 0) rather
	// than erroring the whole response.
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	snap, err := h.collector.Snapshot(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("system stats: snapshot failed")
		writeError(w, http.StatusInternalServerError, "snapshot failed")
		return
	}

	if r.URL.Query().Get("percentiles") != "" {
		// Merge the fast-path snapshot and the rolling-window percentiles
		// into a single object. We marshal the snapshot through a map so
		// we can add the `percentiles` field without having to couple the
		// Stats struct to a handler-level response shape (and without
		// affecting the heartbeat payload, which uses a pinned HBSystem
		// struct that must not grow).
		payload := statsWithPercentiles(snap, h.collector.Percentiles())
		writeJSON(w, http.StatusOK, payload)
		return
	}

	writeJSON(w, http.StatusOK, snap)
}

// statsWithPercentiles returns a flat map merging the standard Stats
// JSON with an added `percentiles` field. Using encoding/json to
// round-trip the Stats struct keeps this in sync with any future field
// additions automatically.
func statsWithPercentiles(snap *sysstat.Stats, pct sysstat.PercentilesSnapshot) map[string]any {
	raw, err := json.Marshal(snap)
	if err != nil {
		// Extremely unlikely (Stats is plain-old-data); fall back to a
		// minimal object so the caller still gets percentile data.
		return map[string]any{"percentiles": pct}
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{"percentiles": pct}
	}
	out["percentiles"] = pct
	return out
}
