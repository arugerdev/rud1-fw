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
	"net/http"
	"strconv"
	"strings"

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
