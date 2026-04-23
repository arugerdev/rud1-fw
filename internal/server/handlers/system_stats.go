package handlers

import (
	"context"
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
	writeJSON(w, http.StatusOK, snap)
}
