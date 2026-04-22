package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/lan"
)

// LANHandler owns the LAN-routing sub-API.
//
// `GET /api/lan/routes`    → current persisted + applied state.
// `POST /api/lan/routes`   → add a single CIDR (idempotent).
// `DELETE /api/lan/routes` → remove a single CIDR by `?subnet=`.
// `PUT /api/lan/routes`    → replace the entire set + toggle enabled flag.
//
// All mutations persist to the same YAML the agent booted from
// (`Config.Save()`) and re-apply the desired set via the shared
// `lan.Manager`. The manager's `Source()` is the device's own WG /24
// derived from the registration code, populated at wiring time.
type LANHandler struct {
	full *config.Config
	mgr  *lan.Manager
	mu   sync.Mutex
}

// NewLANHandler wires a handler. The caller is responsible for calling
// `mgr.Configure(source, uplink)` before the first HTTP request lands; the
// handler re-uses whatever was set there without touching it.
func NewLANHandler(full *config.Config, mgr *lan.Manager) *LANHandler {
	return &LANHandler{full: full, mgr: mgr}
}

// Manager exposes the underlying manager so the agent can trigger Apply
// on startup with the persisted route list.
func (h *LANHandler) Manager() *lan.Manager { return h.mgr }

type lanRouteView struct {
	Subnet  string `json:"subnet"`
	Uplink  string `json:"uplink"`
	Applied bool   `json:"applied"`
}

type lanResponse struct {
	Enabled    bool           `json:"enabled"`
	Uplink     string         `json:"uplink"`
	Source     string         `json:"source"`
	IPForward  bool           `json:"ipForward"`
	Simulated  bool           `json:"simulated"`
	Routes     []lanRouteView `json:"routes"`
}

func (h *LANHandler) current() lanResponse {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Start from the persisted desired set and overlay with the live state.
	desired := append([]string{}, h.full.LAN.Routes...)
	live := h.mgr.Snapshot()
	liveByTarget := make(map[string]lan.Route, len(live))
	for _, r := range live {
		liveByTarget[r.TargetSubnet] = r
	}

	seen := make(map[string]bool, len(desired))
	routes := make([]lanRouteView, 0, len(desired))
	for _, t := range desired {
		if seen[t] {
			continue
		}
		seen[t] = true
		r := lanRouteView{Subnet: t, Uplink: h.mgr.Uplink(), Applied: false}
		if cur, ok := liveByTarget[t]; ok {
			r.Uplink = cur.Uplink
			r.Applied = cur.Applied
		}
		routes = append(routes, r)
	}

	return lanResponse{
		Enabled:   h.full.LAN.Enabled,
		Uplink:    h.mgr.Uplink(),
		Source:    h.mgr.Source(),
		IPForward: lan.IPForwardEnabled(),
		Simulated: h.mgr.Simulated(),
		Routes:    routes,
	}
}

// Get handles GET /api/lan/routes.
func (h *LANHandler) Get(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.current())
}

type lanAddRequest struct {
	Subnet string `json:"subnet"`
}

// Add handles POST /api/lan/routes.
func (h *LANHandler) Add(w http.ResponseWriter, r *http.Request) {
	var req lanAddRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	norm, err := lan.ValidateRoute(req.Subnet, h.mgr.Source())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	for _, existing := range h.full.LAN.Routes {
		if strings.EqualFold(existing, norm) {
			writeJSON(w, http.StatusOK, h.currentLocked())
			return
		}
	}
	h.full.LAN.Routes = append(h.full.LAN.Routes, norm)
	h.reapplyLocked()
	if err := h.full.Save(); err != nil {
		// Roll back in-memory before returning so the file and the manager
		// stay coherent.
		h.full.LAN.Routes = h.full.LAN.Routes[:len(h.full.LAN.Routes)-1]
		h.reapplyLocked()
		log.Error().Err(err).Msg("lan: persist failed")
		writeError(w, http.StatusInternalServerError, "failed to persist config")
		return
	}
	writeJSON(w, http.StatusOK, h.currentLocked())
}

// Remove handles DELETE /api/lan/routes?subnet=<cidr>.
func (h *LANHandler) Remove(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("subnet"))
	if target == "" {
		writeError(w, http.StatusBadRequest, "subnet query parameter is required")
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	idx := -1
	for i, s := range h.full.LAN.Routes {
		if strings.EqualFold(s, target) {
			idx = i
			break
		}
	}
	if idx < 0 {
		writeJSON(w, http.StatusOK, h.currentLocked())
		return
	}
	removed := h.full.LAN.Routes[idx]
	h.full.LAN.Routes = append(h.full.LAN.Routes[:idx], h.full.LAN.Routes[idx+1:]...)
	h.reapplyLocked()
	if err := h.full.Save(); err != nil {
		h.full.LAN.Routes = append(h.full.LAN.Routes, removed)
		h.reapplyLocked()
		log.Error().Err(err).Msg("lan: persist failed")
		writeError(w, http.StatusInternalServerError, "failed to persist config")
		return
	}
	writeJSON(w, http.StatusOK, h.currentLocked())
}

type lanPutRequest struct {
	Enabled *bool     `json:"enabled,omitempty"`
	Uplink  *string   `json:"uplink,omitempty"`
	Routes  *[]string `json:"routes,omitempty"`
}

// Set handles PUT /api/lan/routes. Partial: omit a field to preserve it.
func (h *LANHandler) Set(w http.ResponseWriter, r *http.Request) {
	var req lanPutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	prev := h.full.LAN

	if req.Enabled != nil {
		h.full.LAN.Enabled = *req.Enabled
	}
	if req.Uplink != nil {
		u := strings.TrimSpace(*req.Uplink)
		if u == "" {
			u = lan.DetectDefaultUplink()
		}
		h.full.LAN.UplinkInterface = u
		h.mgr.Configure(h.mgr.Source(), u)
	}
	if req.Routes != nil {
		next := make([]string, 0, len(*req.Routes))
		seen := make(map[string]bool, len(*req.Routes))
		for _, s := range *req.Routes {
			norm, err := lan.ValidateRoute(s, h.mgr.Source())
			if err != nil {
				h.full.LAN = prev
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			if seen[norm] {
				continue
			}
			seen[norm] = true
			next = append(next, norm)
		}
		h.full.LAN.Routes = next
	}

	h.reapplyLocked()
	if err := h.full.Save(); err != nil {
		h.full.LAN = prev
		h.reapplyLocked()
		log.Error().Err(err).Msg("lan: persist failed")
		writeError(w, http.StatusInternalServerError, "failed to persist config")
		return
	}
	writeJSON(w, http.StatusOK, h.currentLocked())
}

// reapplyLocked pushes the desired set into the manager. Caller holds h.mu.
// When LAN is disabled, we push an empty set — rules get torn down but the
// persisted list is kept so the operator can re-enable with one click.
func (h *LANHandler) reapplyLocked() {
	var desired []string
	if h.full.LAN.Enabled {
		desired = append(desired, h.full.LAN.Routes...)
	}
	_, errs := h.mgr.Apply(desired)
	for _, err := range errs {
		log.Warn().Err(err).Msg("lan: apply failed")
	}
}

// currentLocked is the same as current() but assumes the caller holds h.mu.
func (h *LANHandler) currentLocked() lanResponse {
	desired := append([]string{}, h.full.LAN.Routes...)
	live := h.mgr.Snapshot()
	liveByTarget := make(map[string]lan.Route, len(live))
	for _, r := range live {
		liveByTarget[r.TargetSubnet] = r
	}
	seen := make(map[string]bool, len(desired))
	routes := make([]lanRouteView, 0, len(desired))
	for _, t := range desired {
		if seen[t] {
			continue
		}
		seen[t] = true
		r := lanRouteView{Subnet: t, Uplink: h.mgr.Uplink(), Applied: false}
		if cur, ok := liveByTarget[t]; ok {
			r.Uplink = cur.Uplink
			r.Applied = cur.Applied
		}
		routes = append(routes, r)
	}
	return lanResponse{
		Enabled:   h.full.LAN.Enabled,
		Uplink:    h.mgr.Uplink(),
		Source:    h.mgr.Source(),
		IPForward: lan.IPForwardEnabled(),
		Simulated: h.mgr.Simulated(),
		Routes:    routes,
	}
}
