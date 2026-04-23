package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/sysstat/uptime"
	"github.com/rud1-es/rud1-fw/internal/server/httputil"
)

// SystemUptimeEventsExportHandler serves /api/system/uptime-events/export.
//
// Mirrors the audit-style download pattern used by SystemPercentilesExportHandler
// and USBIPHandler.RevocationsExport: operators get a single attachment they can
// archive alongside an incident report rather than scraping the live
// /api/system/uptime-events endpoint and hoping the 200-entry ring hasn't
// rotated past the moment of interest.
//
// The handler only reads from the store — it never mutates state — so a single
// instance is safe to share across requests.
type SystemUptimeEventsExportHandler struct {
	store *uptime.Store
}

// NewSystemUptimeEventsExportHandler wraps an uptime store. A nil store is
// allowed (the handler returns 503) so the agent can degrade gracefully when
// the on-disk file isn't writable.
func NewSystemUptimeEventsExportHandler(store *uptime.Store) *SystemUptimeEventsExportHandler {
	return &SystemUptimeEventsExportHandler{store: store}
}

// uptimeEventExportEntry is the wire-format row. Field names mirror
// uptimeEventItem in system_uptime_events.go so the same downstream renderer
// can consume both endpoints without a translation layer.
type uptimeEventExportEntry struct {
	At            int64  `json:"at"`
	Kind          string `json:"kind"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
	Reason        string `json:"reason"`
}

// uptimeExportMaxWindow caps the requested window at ~1 year; the store only
// holds 200 events so a broader window doesn't surface any extra rows, but the
// cap keeps the filename readable and matches the spirit of pctExportMaxWindow.
const uptimeExportMaxWindow = 365 * 24 * time.Hour

// Export handles GET /api/system/uptime-events/export.
//
// Query params (all optional):
//
//	since  — unix seconds, default = now - uptimeExportMaxWindow
//	until  — unix seconds, default = now
//	format — "jsonl" (default, application/x-ndjson) or "json" (JSON array)
//
// Responses:
//
//	200 — streamed attachment; one line per event (jsonl) or single array (json).
//	      Events are emitted oldest-first so the file reads top-to-bottom as a
//	      traditional audit log.
//	400 — malformed / inverted window or unknown format.
//	503 — store isn't wired (disk unavailable at boot).
//
// Streams via bufio.Writer + json.Encoder with a flush per entry so peak memory
// stays flat — same shape as SystemPercentilesExportHandler.Export.
func (h *SystemUptimeEventsExportHandler) Export(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "uptime events unavailable")
		return
	}

	now := time.Now()
	since, until, err := parseExportWindow(r.URL.Query(), now)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Apply defaults. Raw since/until are retained for the filename so the
	// operator can tell at a glance which call produced which file.
	effSince := since
	if effSince == 0 {
		effSince = now.Add(-uptimeExportMaxWindow).Unix()
	}
	effUntil := until
	if effUntil == 0 {
		effUntil = now.Unix()
	}
	if effSince >= effUntil {
		writeError(w, http.StatusBadRequest, "until must be greater than since")
		return
	}

	// Format selection: matches the other export handlers so a typo doesn't
	// silently fall back to an unexpected shape.
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "jsonl"
	}
	if format != "jsonl" && format != "json" {
		writeError(w, http.StatusBadRequest, "format must be jsonl or json")
		return
	}

	// Pull every event (limit=0 returns the full ring). List yields
	// newest-first; we reverse into chronological order below so the exported
	// file reads top-to-bottom as an audit log — same convention as
	// RevocationsExport / SystemPercentilesExportHandler.
	events := h.store.List(0)
	filtered := make([]uptimeEventExportEntry, 0, len(events))
	for i := len(events) - 1; i >= 0; i-- {
		ev := events[i]
		at := ev.At.Unix()
		if at < effSince || at > effUntil {
			continue
		}
		filtered = append(filtered, uptimeEventExportEntry{
			At:            at,
			Kind:          ev.Kind,
			UptimeSeconds: int64(ev.Uptime.Seconds()),
			Reason:        ev.Reason,
		})
	}

	// Headers MUST be set before any byte of the body, and — critically —
	// before MaybeGzip wraps the writer (gzip starts framing on first Write,
	// so late header mutations silently vanish). Content-Type /
	// Content-Disposition are unchanged by compression; only the filename
	// gains a ".gz" suffix downstream so operators can tell the two variants
	// apart in a Downloads folder.
	ext := format
	filename := fmt.Sprintf("rud1-uptime-%d-%d.%s", effSince, effUntil, ext)
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		filename += ".gz"
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
	}
	w.WriteHeader(http.StatusOK)

	// Transparent gzip layer: returns w unchanged when the client didn't
	// request gzip. closeFn flushes + closes the gzip.Writer trailer and MUST
	// be deferred — skipping it produces a truncated gzip stream.
	bodyW, closeFn := httputil.MaybeGzip(w, r)
	defer func() { _ = closeFn() }()

	bw := bufio.NewWriter(bodyW)
	enc := json.NewEncoder(bw)

	if format == "json" {
		// Stream as a JSON array: hand-rolled brackets/commas so we can
		// flush per element and keep peak memory bounded.
		if _, err := bw.WriteString("["); err != nil {
			log.Warn().Err(err).Msg("uptime: export write failed")
			return
		}
		for i, e := range filtered {
			if i > 0 {
				if _, err := bw.WriteString(","); err != nil {
					log.Warn().Err(err).Msg("uptime: export write failed")
					return
				}
			}
			if err := enc.Encode(e); err != nil {
				log.Warn().Err(err).Msg("uptime: export encode failed")
				return
			}
			if err := bw.Flush(); err != nil {
				log.Warn().Err(err).Msg("uptime: export flush failed")
				return
			}
		}
		if _, err := bw.WriteString("]\n"); err != nil {
			log.Warn().Err(err).Msg("uptime: export write failed")
			return
		}
		_ = bw.Flush()
		return
	}

	// jsonl: one JSON object per line; flush per entry so memory stays flat
	// even for multi-thousand-entry exports.
	for _, e := range filtered {
		if err := enc.Encode(e); err != nil {
			log.Warn().Err(err).Msg("uptime: export encode failed")
			return
		}
		if err := bw.Flush(); err != nil {
			log.Warn().Err(err).Msg("uptime: export flush failed")
			return
		}
	}
}
