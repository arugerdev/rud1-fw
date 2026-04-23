package handlers

import (
	"context"
	"net/http"
	"strconv"
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
	Target      string  `json:"target"`
	Reachable   bool    `json:"reachable"`
	RttMs       float64 `json:"rttMs"`
	PacketLoss  float64 `json:"packetLoss"`
	PacketsSent int     `json:"packetsSent"`
	PacketsRecv int     `json:"packetsRecv"`
	Simulated   bool    `json:"simulated"`
}

// Default and bound constants for the tunable options. The outer context
// timeout must always dominate the ping process's own internal timeout,
// otherwise a slow target gets cut off by Go before ping has a chance to
// print its summary line.
const (
	defaultProbeTimeout = 6 * time.Second
	minProbeTimeout     = 1000 * time.Millisecond
	maxProbeTimeout     = 20000 * time.Millisecond

	defaultProbeCount = 3
	minProbeCount     = 1
	maxProbeCount     = 10
)

// Probe handles GET /api/lan/probe?target=<host-or-ip>[&count=N][&timeout=MS].
func (h *LANProbeHandler) Probe(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	target := strings.TrimSpace(q.Get("target"))
	if err := lan.ValidateTarget(target); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	count := defaultProbeCount
	if raw := strings.TrimSpace(q.Get("count")); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < minProbeCount || v > maxProbeCount {
			writeError(w, http.StatusBadRequest, "count must be an integer in [1,10]")
			return
		}
		count = v
	}

	timeout := defaultProbeTimeout
	if raw := strings.TrimSpace(q.Get("timeout")); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < int(minProbeTimeout/time.Millisecond) || v > int(maxProbeTimeout/time.Millisecond) {
			writeError(w, http.StatusBadRequest, "timeout must be an integer (ms) in [1000,20000]")
			return
		}
		timeout = time.Duration(v) * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	// Divide the outer budget across the packets so a single -W cap can't
	// outlast the HTTP context. Integer ms division with a 1s floor matches
	// the clamp inside Prober.Ping.
	perPing := timeout / time.Duration(count)
	if perPing < time.Second {
		perPing = time.Second
	}

	res, err := h.prober.Ping(ctx, target, lan.PingOptions{
		Count:          count,
		PerPingTimeout: perPing,
	})
	if err != nil {
		log.Warn().Err(err).Str("target", target).Msg("lan: probe failed")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, lanProbeResponse{
		Target:      res.Target,
		Reachable:   res.Reachable,
		RttMs:       res.RttMs,
		PacketLoss:  res.PacketLoss,
		PacketsSent: res.PacketsSent,
		PacketsRecv: res.PacketsRecv,
		Simulated:   platform.SimulateHardware(),
	})
}
