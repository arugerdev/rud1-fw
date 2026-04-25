// Package handlers — config-mutation audit log read endpoint.
//
// The audit log is appended to by other handlers (timezone, ntp-probe,
// setup) on every successful or failed mutation. This handler exposes
// the same data to operators for debugging "who/what/when changed"
// across reboots and log rotations.
//
// Endpoint (BearerAuth):
//
//	GET /api/system/audit?action=&since=&until=&limit=&offset=
//	GET /api/system/audit/retention
//	PUT /api/system/audit/retention  body: {"days":N}
//
// Response shape:
//
//	{"entries":[...newest-first...], "total":N}
//
// The handler is a thin shim around configlog.Logger — the package owns
// all the rotation / retention / I/O logic.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/audit/configlog"
)

// auditLogger is the small subset other handlers depend on so the
// infrastructure package isn't pulled into every handler file. Both
// configlog.DiskLogger and configlog.LoggerNoop satisfy it.
type auditLogger interface {
	Append(ctx context.Context, e configlog.Entry) error
}

// SystemAuditHandler serves GET /api/system/audit. It owns no state
// beyond the configlog.Logger pointer; querying is stateless.
type SystemAuditHandler struct {
	log configlog.Logger
}

// NewSystemAuditHandler wires a handler around any configlog.Logger
// implementation. Pass configlog.LoggerNoop{} when no disk logger is
// available — the handler still serves a 200 with an empty list so
// the UI doesn't have to special-case "audit unavailable".
func NewSystemAuditHandler(l configlog.Logger) *SystemAuditHandler {
	if l == nil {
		l = configlog.LoggerNoop{}
	}
	return &SystemAuditHandler{log: l}
}

// auditListResponse is the wire shape returned by GET. `entries` is
// newest-first; `total` is the unpaginated post-filter count so the UI
// can render a "X of Y" pager.
type auditListResponse struct {
	Entries []configlog.Entry `json:"entries"`
	Total   int               `json:"total"`
}

const (
	// auditDefaultLimit / auditMaxLimit bound the page size. The cap
	// mirrors the revocations endpoint — a paged list is cheap to
	// re-issue and a 200-row payload comfortably fits in mobile
	// memory.
	auditDefaultLimit = 50
	auditMaxLimit     = 200
)

// List — GET /api/system/audit. Validates the query string with the
// same shape as /api/usbip/revocations: bare numeric strings,
// rejection on negatives or out-of-range, default fill on missing.
func (h *SystemAuditHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := auditDefaultLimit
	if s := strings.TrimSpace(q.Get("limit")); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 0 {
			writeError(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return
		}
		if v > auditMaxLimit {
			writeError(w, http.StatusBadRequest, "limit must be <= "+strconv.Itoa(auditMaxLimit))
			return
		}
		limit = v
	}
	offset := 0
	if s := strings.TrimSpace(q.Get("offset")); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 0 {
			writeError(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		offset = v
	}
	var since, until int64
	if s := strings.TrimSpace(q.Get("since")); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil || v < 0 {
			writeError(w, http.StatusBadRequest, "since must be a non-negative unix-second integer")
			return
		}
		since = v
	}
	if s := strings.TrimSpace(q.Get("until")); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil || v < 0 {
			writeError(w, http.StatusBadRequest, "until must be a non-negative unix-second integer")
			return
		}
		until = v
	}
	action := strings.TrimSpace(q.Get("action"))

	filter := configlog.ListOptions{Since: since, Until: until, Action: action}

	// Total is computed against the same filter (sans pagination) so
	// the client can drive a pager without re-issuing the query for
	// each page change. Implementations that don't expose Total
	// (LoggerNoop is fine — its List is empty) fall back to a List
	// pass.
	var total int
	if t, ok := h.log.(interface {
		Total(opts configlog.ListOptions) (int, error)
	}); ok {
		n, err := t.Total(filter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "audit total failed: "+err.Error())
			return
		}
		total = n
	} else {
		all, err := h.log.List(filter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "audit list failed: "+err.Error())
			return
		}
		total = len(all)
	}

	page := filter
	page.Limit = limit
	page.Offset = offset
	entries, err := h.log.List(page)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit list failed: "+err.Error())
		return
	}
	if entries == nil {
		entries = []configlog.Entry{}
	}
	writeJSON(w, http.StatusOK, auditListResponse{Entries: entries, Total: total})
}

// retentionPruner is the narrow contract the Set handler depends on —
// keeping it as an interface (rather than calling *configlog.DiskLogger
// directly) lets tests stub the prune to verify call counts and force
// error paths without touching the real disk-backed logger.
//
// SetMaxFiles reconfigures the active retention bound and returns the
// previous value; PruneOld runs an immediate sweep and returns the
// number of day-files removed.
type retentionPruner interface {
	SetMaxFiles(n int) int
	PruneOld() (int, error)
}

// SystemAuditRetentionHandler serves GET / PUT /api/system/audit/retention.
// It exposes the effective retention configuration plus disk-inventory
// stats so operators can answer "how much history do I really have",
// and accepts a PUT body of {"days":N} to mutate the retention window
// at runtime.
//
// The mutex guards the persist-then-prune sequence on Set so two
// concurrent PUTs can't race on cfg.Save() / SetMaxFiles / PruneOld.
type SystemAuditRetentionHandler struct {
	mu       sync.Mutex
	cfg      *config.Config
	log      *configlog.DiskLogger
	pruner   retentionPruner // injectable for tests; nil means "use h.log"
	auditLog auditLogger     // never nil after construction (LoggerNoop default)
}

// NewSystemAuditRetentionHandler wires the handler. log may be nil when
// the agent is running on a read-only fs / the disk logger failed to
// open; the handler still serves a 200 with the configured/effective
// retention numbers and zero stats so the UI can render unconditionally.
func NewSystemAuditRetentionHandler(cfg *config.Config, log *configlog.DiskLogger) *SystemAuditRetentionHandler {
	h := &SystemAuditRetentionHandler{cfg: cfg, log: log, auditLog: configlog.LoggerNoop{}}
	if log != nil {
		h.pruner = log
	}
	return h
}

// SetAuditLogger swaps in a real audit logger after construction. Wired
// from agent.go where the configlog.DiskLogger is built. Calling with
// nil reverts to the no-op logger.
func (h *SystemAuditRetentionHandler) SetAuditLogger(l auditLogger) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if l == nil {
		h.auditLog = configlog.LoggerNoop{}
		return
	}
	h.auditLog = l
}

// setPrunerForTest overrides the retention pruner — exclusively for
// table-driven tests that need to assert call counts or force the
// PruneOld path to error. Production callers should never invoke this.
func (h *SystemAuditRetentionHandler) setPrunerForTest(p retentionPruner) {
	h.mu.Lock()
	h.pruner = p
	h.mu.Unlock()
}

// auditRetentionResponse is the wire shape for GET /api/system/audit/retention.
// Pointer time fields are omitted on the wire when zero so the UI can
// distinguish "no data yet" from "epoch zero".
type auditRetentionResponse struct {
	ConfiguredDays int        `json:"configuredDays"`
	EffectiveDays  int        `json:"effectiveDays"`
	Default        int        `json:"default"`
	MinDays        int        `json:"minDays"`
	MaxDays        int        `json:"maxDays"`
	TotalEntries   int        `json:"totalEntries"`
	TotalBytes     int64      `json:"totalBytes"`
	FileCount      int        `json:"fileCount"`
	OldestEntryAt  *time.Time `json:"oldestEntryAt,omitempty"`
	NewestEntryAt  *time.Time `json:"newestEntryAt,omitempty"`
	LastPruneAt    *time.Time `json:"lastPruneAt,omitempty"`
}

// Get — GET /api/system/audit/retention. The configured/effective
// numbers come straight from the config helpers (so the clamp logic
// has a single source of truth); inventory stats come from the disk
// logger when available.
func (h *SystemAuditRetentionHandler) Get(w http.ResponseWriter, _ *http.Request) {
	resp := auditRetentionResponse{
		ConfiguredDays: h.cfg.System.AuditRetentionDays,
		EffectiveDays:  h.cfg.System.AuditRetentionDaysOrDefault(),
		Default:        config.DefaultAuditRetentionDays,
		MinDays:        config.MinAuditRetentionDays,
		MaxDays:        config.MaxAuditRetentionDays,
	}
	if h.log != nil {
		stats, err := h.log.Stats()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "audit stats failed: "+err.Error())
			return
		}
		resp.TotalEntries = stats.TotalEntries
		resp.TotalBytes = stats.TotalBytes
		resp.FileCount = stats.FileCount
		if !stats.OldestEntryAt.IsZero() {
			t := stats.OldestEntryAt.UTC()
			resp.OldestEntryAt = &t
		}
		if !stats.NewestEntryAt.IsZero() {
			t := stats.NewestEntryAt.UTC()
			resp.NewestEntryAt = &t
		}
		if !stats.LastPruneAt.IsZero() {
			t := stats.LastPruneAt.UTC()
			resp.LastPruneAt = &t
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// auditRetentionUpdateRequest is the body shape accepted by PUT. Only
// `days` is mutable today; future fields can join without breaking the
// existing wire contract.
type auditRetentionUpdateRequest struct {
	Days *int `json:"days,omitempty"`
}

// Set — PUT /api/system/audit/retention. Validates the requested days
// against the [Min, Max] window, persists cfg via Save(), and — when
// the new bound is strictly smaller than the previous effective value —
// reconfigures the live disk logger AND triggers an immediate prune so
// out-of-window day-files are deleted right away rather than lingering
// until the next natural rotation.
//
// Growing or unchanged retention is intentionally a no-op on the disk
// path: there is nothing to delete, and a stray prune call would only
// nudge lastPruneAt forward and confuse "nothing changed yet" UI.
//
// Persist failures roll back the in-memory mutation and return 500.
// Prune failures are best-effort: the persisted retention stands, the
// error is warn-logged, and the response is still 200 OK so cloud
// telemetry doesn't get a misleading failure for a successful config
// change. This mirrors the timezone handler's "audit append failure
// never propagates" pattern.
func (h *SystemAuditRetentionHandler) Set(w http.ResponseWriter, r *http.Request) {
	var req auditRetentionUpdateRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if req.Days == nil {
		writeError(w, http.StatusBadRequest, "body must contain `days`")
		return
	}
	days := *req.Days
	if days < config.MinAuditRetentionDays || days > config.MaxAuditRetentionDays {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("days must be in [%d,%d]", config.MinAuditRetentionDays, config.MaxAuditRetentionDays))
		return
	}

	h.mu.Lock()
	prevEffective := h.cfg.System.AuditRetentionDaysOrDefault()
	prevConfigured := h.cfg.System.AuditRetentionDays
	h.cfg.System.AuditRetentionDays = days
	auditL := h.auditLog
	pruner := h.pruner

	if saveErr := h.cfg.Save(); saveErr != nil {
		h.cfg.System.AuditRetentionDays = prevConfigured
		h.mu.Unlock()
		log.Error().Err(saveErr).Msg("audit-retention: failed to persist update")
		if auditL != nil {
			if err := auditL.Append(r.Context(), configlog.Entry{
				Action:   "system.audit.retention.set",
				Actor:    "operator",
				Previous: map[string]any{"days": prevConfigured},
				Next:     nil,
				OK:       false,
				Error:    "save: " + saveErr.Error(),
			}); err != nil {
				log.Warn().Err(err).Msg("audit append failed (non-fatal)")
			}
		}
		writeError(w, http.StatusInternalServerError, "failed to persist config: "+saveErr.Error())
		return
	}

	newEffective := h.cfg.System.AuditRetentionDaysOrDefault()
	shrunk := newEffective < prevEffective
	var pruned int
	var pruneErr error
	if shrunk && pruner != nil {
		// Reconfigure the live retention bound first so the prune
		// sweep deletes against the NEW window, not the old one.
		pruner.SetMaxFiles(newEffective)
		pruned, pruneErr = pruner.PruneOld()
	}
	h.mu.Unlock()

	if shrunk {
		if pruneErr != nil {
			log.Warn().
				Err(pruneErr).
				Int("oldDays", prevEffective).
				Int("newDays", newEffective).
				Msg("audit retention shrunk; immediate prune failed (non-fatal)")
		} else if pruner != nil {
			log.Info().
				Int("oldDays", prevEffective).
				Int("newDays", newEffective).
				Int("pruned", pruned).
				Msg("audit retention shrunk; immediate prune ran")
		}
	}

	if auditL != nil {
		if err := auditL.Append(r.Context(), configlog.Entry{
			Action:   "system.audit.retention.set",
			Actor:    "operator",
			Previous: map[string]any{"days": prevConfigured},
			Next:     map[string]any{"days": days},
			OK:       true,
		}); err != nil {
			log.Warn().Err(err).Msg("audit append failed (non-fatal)")
		}
	}

	// Reuse the GET path's wire shape so cloud / UI consumers see the
	// same response on PUT as they would on a follow-up GET.
	h.Get(w, r)
}
