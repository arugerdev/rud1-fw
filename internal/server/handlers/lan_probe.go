package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/infrastructure/lan"
	"github.com/rud1-es/rud1-fw/internal/platform"
)

// LANProbeHandler exposes a reachability probe so rud1-app can ask the Pi
// to ping a host on its LAN before the operator wires up an exposure rule.
// It is deliberately separate from LANHandler — probing is read-only and
// doesn't touch the persisted route list.
type LANProbeHandler struct {
	prober *lan.Prober
}

// NewLANProbeHandler constructs a probe handler. The prober is stateless so
// sharing a single instance across requests is safe.
func NewLANProbeHandler(prober *lan.Prober) *LANProbeHandler {
	return &LANProbeHandler{prober: prober}
}

// lanProbeResponse is the JSON shape returned by GET /api/lan/probe. The
// `simulated` flag mirrors the one on /api/lan/routes so rud1-app can show
// a single "rules are simulated" banner regardless of which sub-endpoint
// produced the data.
type lanProbeResponse struct {
	Target     string  `json:"target"`
	Reachable  bool    `json:"reachable"`
	RttMs      float64 `json:"rttMs"`
	PacketLoss float64 `json:"packetLoss"`
	Simulated  bool    `json:"simulated"`
}

// probeTimeout is the upper bound on a single probe request. `ping -c 3
// -W 2` can spend at most ~6s in the worst case (3 × 2s per-packet
// timeout), which is why the HTTP context is sized to match.
const probeTimeout = 6 * time.Second

// Probe handles GET /api/lan/probe?target=<host-or-ip>.
func (h *LANProbeHandler) Probe(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if err := lan.ValidateTarget(target); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
	defer cancel()

	res, err := h.prober.Ping(ctx, target)
	if err != nil {
		log.Warn().Err(err).Str("target", target).Msg("lan: probe failed")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, lanProbeResponse{
		Target:     res.Target,
		Reachable:  res.Reachable,
		RttMs:      res.RttMs,
		PacketLoss: res.PacketLoss,
		Simulated:  platform.SimulateHardware(),
	})
}
