// Cloud→agent desired-config last-applied surface (iter 52).
//
// `GET /api/system/desired-config/last-applied` exposes the wall-clock
// time and the canonical wire-name list of fields the cloud most
// recently pushed that actually landed on disk. The local panel
// (rud1-app) reads this to render a "last cloud push converged at …"
// chip on the device-detail page WITHOUT round-tripping through
// rud1-es — useful when an operator on-site wants to confirm
// convergence while diagnosing a transient cloud-link drop.
//
// Read-only. No side effects. Safe for any role with bearer auth.

package handlers

import (
	"net/http"
	"time"
)

// DesiredConfigLastAppliedSource is the minimal sliver of the agent's
// `desiredConfigApplier` the handler needs. Defined as an interface so
// the handler stays free of the `application/agent` import (the agent
// imports the handlers package, not the other way around) AND so tests
// can stub the source without spinning up a full applier.
//
// Both methods may return nil — a freshly-booted device that has never
// received a cloud push returns (nil, nil) and the handler emits a 200
// with `lastAppliedAt: null, fields: []` so the UI can render
// unconditionally.
type DesiredConfigLastAppliedSource interface {
	LastAppliedAt() *time.Time
	LastAppliedFields() []string
}

// SystemDesiredConfigHandler serves the iter-52 `last-applied` endpoint.
// Stateless — every call re-reads the live applier state.
type SystemDesiredConfigHandler struct {
	src DesiredConfigLastAppliedSource
}

// NewSystemDesiredConfigHandler wires the handler. `src` may be nil on
// the dev/test path where the agent didn't construct a desiredConfig
// applier; the handler then serves a 200 with empty values rather than
// a 503, mirroring the local-panel-renders-unconditionally contract.
func NewSystemDesiredConfigHandler(src DesiredConfigLastAppliedSource) *SystemDesiredConfigHandler {
	return &SystemDesiredConfigHandler{src: src}
}

// desiredConfigLastAppliedResponse is the wire shape. Fields are always
// present — `lastAppliedAt` is null when no apply has ever run, `fields`
// is an empty array (NEVER null) so the UI can do a length check
// without a defensive nil-guard.
type desiredConfigLastAppliedResponse struct {
	LastAppliedAt *time.Time `json:"lastAppliedAt"`
	Fields        []string   `json:"fields"`
}

// LastApplied — GET /api/system/desired-config/last-applied.
func (h *SystemDesiredConfigHandler) LastApplied(w http.ResponseWriter, _ *http.Request) {
	resp := desiredConfigLastAppliedResponse{Fields: []string{}}
	if h.src != nil {
		if t := h.src.LastAppliedAt(); t != nil {
			utc := t.UTC()
			resp.LastAppliedAt = &utc
		}
		if f := h.src.LastAppliedFields(); len(f) > 0 {
			resp.Fields = f
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
