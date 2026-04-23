package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/lan"
)

// LANTracerouteHandler exposes a traceroute probe so rud1-app can show the
// hop-by-hop path the Pi sees to a LAN or Internet target. Read-only; no
// side effects on iptables or the persisted route list.
type LANTracerouteHandler struct {
	tracer *lan.Tracer
}

// NewLANTracerouteHandler constructs a traceroute handler. The tracer is
// stateless so sharing a single instance across requests is safe.
func NewLANTracerouteHandler(tracer *lan.Tracer) *LANTracerouteHandler {
	return &LANTracerouteHandler{tracer: tracer}
}

// Query-param bounds. 30 hops is traceroute's own historical default max; we
// cap at 30 to keep worst-case duration bounded inside the 30s context.
const (
	traceTimeout   = 30 * time.Second
	defaultMaxHops = 15
	minMaxHops     = 1
	maxMaxHops     = 30
)

// Trace handles GET /api/lan/traceroute?target=<host-or-ip>[&maxHops=N].
func (h *LANTracerouteHandler) Trace(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := strings.TrimSpace(q.Get("target"))
	if err := lan.ValidateTarget(target); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	maxHops := defaultMaxHops
	if raw := strings.TrimSpace(q.Get("maxHops")); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < minMaxHops || v > maxMaxHops {
			writeError(w, http.StatusBadRequest, "maxHops must be an integer in [1,30]")
			return
		}
		maxHops = v
	}

	ctx, cancel := context.WithTimeout(r.Context(), traceTimeout)
	defer cancel()

	res, err := h.tracer.Trace(ctx, target, lan.TraceOptions{MaxHops: maxHops})
	if err != nil {
		log.Warn().Err(err).Str("target", target).Msg("lan: traceroute failed")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, res)
}
