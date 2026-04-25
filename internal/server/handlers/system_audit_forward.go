// Package handlers — audit-log forward-shipping status endpoint (iter 40).
//
// Surfaces the heartbeat audit-cursor state to operators so a stuck or
// lagging cloud-forward can be diagnosed from the local panel without
// having to read the agent log. The shape mirrors the forward bookkeeping
// the agent maintains on its own (auditCursor + on-disk auditLog) and
// adds a derived `pendingCount` so the UI can show "X entries waiting to
// ship" at a glance.
//
// Endpoint (BearerAuth):
//
//	GET /api/system/audit/forward-status
//
// Response shape:
//
//	{
//	  "auditAvailable": true,
//	  "cloudEnabled": true,
//	  "cursorAt": "2026-04-25T12:00:00Z",     // omitted when unset
//	  "pendingCount": 3,
//	  "oldestPendingAt": "2026-04-25T13:30:00Z", // omitted when none
//	  "newestPendingAt": "2026-04-25T14:15:00Z"  // omitted when none
//	}
//
// The handler is read-only and does no I/O outside the configlog snapshot
// it requests for the pending-count window.
package handlers

import (
	"net/http"
	"time"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/audit/configlog"
)

// AuditCursorSource is the narrow accessor the handler needs to read the
// agent's last-shipped cursor without taking a hard dependency on the
// agent package (which would create an import cycle).
type AuditCursorSource interface {
	// AuditCursor returns the timestamp of the newest audit entry the
	// agent has successfully shipped to the cloud. Zero time means the
	// cursor has never advanced (first boot of an upgraded agent), in
	// which case the handler reports `cursorAt` as omitted and the
	// pending-count window opens at the start of the on-disk audit log.
	AuditCursor() time.Time
}

// SystemAuditForwardStatusHandler is stateless beyond the wiring it
// receives at construction. It re-reads the cursor on every request so
// the response always reflects the live in-memory agent state.
type SystemAuditForwardStatusHandler struct {
	cursorSrc    AuditCursorSource
	log          configlog.Logger
	cloudEnabled bool
}

// NewSystemAuditForwardStatusHandler wires a handler. cursorSrc may be
// nil on dev paths where no agent is attached (the handler reports a
// zero cursor); auditLog may be nil when the disk logger failed to
// open (LoggerNoop fallback). cloudEnabled mirrors cfg.Cloud.Enabled —
// when false the agent never ships audit entries regardless of cursor
// state, and the UI surfaces a "cloud disabled" hint instead of a
// pending-count.
func NewSystemAuditForwardStatusHandler(cursorSrc AuditCursorSource, auditLog configlog.Logger, cloudEnabled bool) *SystemAuditForwardStatusHandler {
	if auditLog == nil {
		auditLog = configlog.LoggerNoop{}
	}
	return &SystemAuditForwardStatusHandler{
		cursorSrc:    cursorSrc,
		log:          auditLog,
		cloudEnabled: cloudEnabled,
	}
}

// auditForwardStatusResponse is the wire shape returned by GET. Pointer
// time fields are omitted on the wire when zero so the UI can
// distinguish "no data" from "epoch zero".
type auditForwardStatusResponse struct {
	AuditAvailable  bool       `json:"auditAvailable"`
	CloudEnabled    bool       `json:"cloudEnabled"`
	CursorAt        *time.Time `json:"cursorAt,omitempty"`
	PendingCount    int        `json:"pendingCount"`
	OldestPendingAt *time.Time `json:"oldestPendingAt,omitempty"`
	NewestPendingAt *time.Time `json:"newestPendingAt,omitempty"`
}

// Status — GET /api/system/audit/forward-status. Reads the cursor,
// asks the audit logger for entries strictly newer than the cursor,
// and returns the count + oldest/newest timestamps of that pending
// window. The same `cursor.Unix() + 1` strict-newer-than offset that
// the agent uses internally is replicated here so the count matches
// what the next heartbeat would actually ship.
func (h *SystemAuditForwardStatusHandler) Status(w http.ResponseWriter, _ *http.Request) {
	resp := auditForwardStatusResponse{
		AuditAvailable: true,
		CloudEnabled:   h.cloudEnabled,
	}

	// LoggerNoop is the sentinel we treat as "audit unavailable" — its
	// List always returns an empty slice so we couldn't distinguish a
	// noop from a healthy-but-empty logger by listing alone.
	if _, isNoop := h.log.(configlog.LoggerNoop); isNoop {
		resp.AuditAvailable = false
		writeJSON(w, http.StatusOK, resp)
		return
	}

	var cursor time.Time
	if h.cursorSrc != nil {
		cursor = h.cursorSrc.AuditCursor()
	}
	if !cursor.IsZero() {
		c := cursor.UTC()
		resp.CursorAt = &c
	}

	since := int64(0)
	if !cursor.IsZero() {
		// Mirror buildHeartbeatAudit's strict "newer than cursor"
		// offset so the count surfaces what the next tick would
		// actually emit.
		since = cursor.Unix() + 1
	}
	rows, err := h.log.List(configlog.ListOptions{Since: since})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit forward status: list failed: "+err.Error())
		return
	}
	resp.PendingCount = len(rows)
	if len(rows) > 0 {
		// configlog.List returns newest-first, so the slice's first
		// element is the newest pending and the last element is the
		// oldest pending. We surface both so the UI can render
		// "pending since X, latest at Y" without re-fetching.
		newest := time.Unix(rows[0].At, 0).UTC()
		oldest := time.Unix(rows[len(rows)-1].At, 0).UTC()
		resp.NewestPendingAt = &newest
		resp.OldestPendingAt = &oldest
	}
	writeJSON(w, http.StatusOK, resp)
}
