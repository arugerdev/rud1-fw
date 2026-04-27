// Package server wires together the Chi router, middleware, and HTTP handlers
// for the local rud1-agent API (consumed by rud1-app).
package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/server/handlers"
	apimiddleware "github.com/rud1-es/rud1-fw/internal/server/middleware"
)

// Server is the local HTTP API server.
type Server struct {
	cfg        *config.Config
	router     *chi.Mux
	httpServer *http.Server
	usbipH     *handlers.USBIPHandler
}

// New assembles the Server with all routes and middleware.
//
// usbipH is shared with the agent's heartbeat loop so the authoritative
// ExportedDevices() list comes from a single USBIPServer instance.
func New(
	cfg *config.Config,
	systemH *handlers.SystemHandler,
	networkH *handlers.NetworkHandler,
	vpnH *handlers.VPNHandler,
	vpnPeerH *handlers.VPNPeerHandler,
	vpnPeersSumH *handlers.VPNPeersSummaryHandler,
	vpnPeerDetailH *handlers.VPNPeerDetailHandler,
	vpnThroughputH *handlers.VPNThroughputHandler,
	usbH *handlers.USBHandler,
	usbipH *handlers.USBIPHandler,
	connH *handlers.ConnectivityHandler,
	identityH *handlers.IdentityHandler,
	lanH *handlers.LANHandler,
	lanProbeH *handlers.LANProbeHandler,
	lanTraceH *handlers.LANTracerouteHandler,
	sysStatsH *handlers.SystemStatsHandler,
	sysHealthH *handlers.SystemHealthHandler,
	sysPctHistH *handlers.SystemPercentilesHistoryHandler,
	sysPctExpH *handlers.SystemPercentilesExportHandler,
	sysUptimeEvH *handlers.SystemUptimeEventsHandler,
	sysUptimeEvExpH *handlers.SystemUptimeEventsExportHandler,
	sysUptimeSumH *handlers.SystemUptimeSummaryHandler,
	setupH *handlers.SetupHandler,
	sysTzH *handlers.SystemTimezoneHandler,
	sysTimeHealthH *handlers.SystemTimeHealthHandler,
	sysNTPProbeCfgH *handlers.SystemNTPProbeConfigHandler,
	sysAuditH *handlers.SystemAuditHandler,
	sysAuditRetH *handlers.SystemAuditRetentionHandler,
	sysAuditFwdH *handlers.SystemAuditForwardStatusHandler,
	sysDesiredCfgH *handlers.SystemDesiredConfigHandler,
) *Server {

	r := chi.NewRouter()

	// Global middleware — order matters.
	r.Use(cors.Handler(cors.Options{
		// We use a function rather than a static list because the
		// local panel (rud1-app, served on port 80 by the embedded
		// web server) and the firmware API (this server, port 7070)
		// live on the SAME host but DIFFERENT ports — and that counts
		// as a cross-origin request from the browser's perspective.
		// Same-host-any-port is the canonical pattern for a panel +
		// API combo on a single appliance, so we allow it explicitly
		// in addition to the configured origin list.
		AllowOriginFunc:  allowOriginFunc(cfg.Server.AllowedOrigins),
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	r.Use(apimiddleware.Recovery())
	r.Use(apimiddleware.RequestLogger())
	r.Use(chimiddleware.Compress(5))

	// Health endpoint — no auth required.
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}` + "\n"))
	})

	// Identity — NO auth required because rud1-app displays this to the
	// user during setup (before any token is agreed on) and the info is
	// the same as what's printed on the device's sticker. Binding the
	// local API to LAN only keeps the blast radius the same as physical
	// access, which is the intended trust model.
	r.Get("/api/identity", identityH.Get)

	// Setup wizard — same chicken-and-egg pattern as /api/identity but
	// with a stricter gate: once cfg.Setup.Complete flips to true,
	// these endpoints fall back to BearerAuth so a paired device
	// doesn't leave a mutation surface open on its LAN. /reset is in
	// the authenticated group below since it's destructive.
	r.Group(func(r chi.Router) {
		r.Use(handlers.SetupGate(cfg, cfg.Server.AuthToken))
		r.Get("/api/setup/state", setupH.State)
		r.Get("/api/setup/health", setupH.Health)
		r.Post("/api/setup/general", setupH.General)
		r.Post("/api/setup/complete", setupH.Complete)
		// Wizard NTP probe step (iter 35). Curated defaults +
		// validate/persist/probe one-shot — same gate semantics as the
		// rest of the wizard: open before Setup.Complete=true, bearer
		// after.
		r.Get("/api/setup/ntp/defaults", setupH.NTPDefaults)
		r.Post("/api/setup/ntp", setupH.NTPApply)
	})

	// Authenticated API routes.
	r.Group(func(r chi.Router) {
		r.Use(apimiddleware.BearerAuth(cfg.Server.AuthToken))

		r.Get("/api/system/info", systemH.Info)
		r.Get("/api/system/stats", sysStatsH.Stats)
		r.Get("/api/system/health", sysHealthH.Health)
		r.Get("/api/system/uptime-events", sysUptimeEvH.Events)
		r.Get("/api/system/uptime-events/export", sysUptimeEvExpH.Export)
		r.Get("/api/system/uptime-summary", sysUptimeSumH.Summary)
		r.Get("/api/system/timezone", sysTzH.Get)
		r.Post("/api/system/timezone", sysTzH.Set)
		r.Get("/api/system/time-health", sysTimeHealthH.TimeHealth)
		r.Get("/api/system/ntp-probe-config", sysNTPProbeCfgH.Get)
		r.Put("/api/system/ntp-probe-config", sysNTPProbeCfgH.Set)
		// Persistent audit log of runtime config mutations (timezone,
		// ntp-probe, setup wizard). See internal/infrastructure/audit/configlog.
		r.Get("/api/system/audit", sysAuditH.List)
		// Retention configuration + on-disk inventory for the audit log.
		// PUT mutates the retention window at runtime; iter 39 wired an
		// immediate prune-on-shrink so a freshly-tightened window is
		// reflected on disk without waiting for the next rotation.
		r.Get("/api/system/audit/retention", sysAuditRetH.Get)
		r.Put("/api/system/audit/retention", sysAuditRetH.Set)
		// Iter 40: heartbeat audit-forward cursor + pending-count
		// snapshot. Read-only; surfaces what the next heartbeat tick
		// would ship so operators can diagnose a stuck cloud-forward
		// without reading the agent log.
		r.Get("/api/system/audit/forward-status", sysAuditFwdH.Status)
		// Iter 52: cloud→agent convergence chip. Returns the wall-clock
		// time + the canonical field-name list of the most recent
		// successful desired-config Apply, so the local panel can show
		// "last cloud push converged at … (fields: …)" without round-
		// tripping through rud1-es.
		r.Get("/api/system/desired-config/last-applied", sysDesiredCfgH.LastApplied)
		r.Get("/api/percentiles/history", sysPctHistH.History)
		r.Get("/api/percentiles/export", sysPctExpH.Export)
		r.Post("/api/system/reboot", systemH.Reboot)

		r.Get("/api/network/status", networkH.Status)

		// Connectivity (WiFi client + cellular modem + setup AP).
		// These routes MUST remain reachable even when the device is in AP
		// mode — that's the whole point. BearerAuth is still enforced if
		// the user configured an auth_token; otherwise it's open on-LAN.
		r.Get("/api/network/connectivity", connH.Snapshot)
		r.Post("/api/network/connectivity/preferred", connH.SetPreferred)

		r.Get("/api/network/wifi/scan", connH.WiFiScan)
		r.Get("/api/network/wifi/saved", connH.WiFiSaved)
		r.Get("/api/network/wifi/status", connH.WiFiStatus)
		r.Post("/api/network/wifi/connect", connH.WiFiConnect)
		r.Post("/api/network/wifi/disconnect", connH.WiFiDisconnect)
		r.Delete("/api/network/wifi/saved/{ssid}", connH.WiFiForget)

		r.Get("/api/network/cellular", connH.CellularStatus)
		r.Post("/api/network/cellular/config", connH.CellularSetConfig)
		r.Post("/api/network/cellular/pin", connH.CellularUnlockPIN)
		r.Post("/api/network/cellular/connect", connH.CellularConnect)
		r.Post("/api/network/cellular/disconnect", connH.CellularDisconnect)

		r.Get("/api/network/ap", connH.APStatus)
		r.Post("/api/network/ap", connH.APSet)
		r.Put("/api/network/ap/credentials", connH.APSetCredentials)

		r.Get("/api/vpn/status", vpnH.Status)
		r.Post("/api/vpn/reconnect", vpnH.Reconnect)
		r.Post("/api/vpn/config", vpnH.ApplyConfig)

		// WG server peer management (list / add / remove). Add/Remove is
		// out-of-band relative to the cloud-driven heartbeat sync —
		// useful for rud1-app admin tasks and disconnected installs.
		r.Get("/api/vpn/peers", vpnPeerH.List)
		r.Post("/api/vpn/peers", vpnPeerH.Add)
		r.Delete("/api/vpn/peers", vpnPeerH.Remove)

		// Precomputed dashboard tile: peer counts + handshake aggregates
		// within a short enumerated window. Mirrors /api/system/uptime-
		// summary — saves mobile clients from reducing the full peer
		// list on every poll.
		r.Get("/api/vpn/peers/summary", vpnPeersSumH.Summary)

		// Per-peer drill-down — companion to /summary. Returns one peer
		// object with bytes, endpoint, and handshake age so the UI can
		// open a detail panel from a row tap without re-fetching the
		// whole list. Pubkey is validated client-side before hitting wg.
		r.Get("/api/vpn/peers/{pubkey}", vpnPeerDetailH.Detail)

		// Bandwidth tile — returns cumulative + windowed bytesTx/Rx
		// fleet-wide for the WG iface, plus a top-N peer breakdown
		// for the trend chart. Strict-parse window={1h,6h,24h,7d}.
		r.Get("/api/vpn/throughput", vpnThroughputH.Throughput)

		// LAN routing — opt-in exposure of the Pi's LAN subnet(s) over the
		// WireGuard tunnel. Mutations persist to config.yaml via
		// config.Config.Save (same mechanism USB policy uses).
		r.Get("/api/lan/routes", lanH.Get)
		r.Post("/api/lan/routes", lanH.Add)
		r.Put("/api/lan/routes", lanH.Set)
		r.Delete("/api/lan/routes", lanH.Remove)

		// LAN reachability probe — read-only, does not touch iptables.
		// Lets rud1-app validate a host/IP before asking the operator to
		// commit a new route.
		r.Get("/api/lan/probe", lanProbeH.Probe)
		r.Get("/api/lan/traceroute", lanTraceH.Trace)

		r.Get("/api/usb/devices", usbH.List)

		// USB/IP server management (authorized nets only).
		//
		// export/attach and unexport/detach are intentional aliases — the
		// former match `usbip bind/unbind` terminology and the latter match
		// the client-facing "attach/detach" verbs used by rud1-es Connect
		// tab and the rud1-desktop Electron bridge. Both paths go through
		// the same policy-checked code path.
		r.Get("/api/usbip/status", usbipH.Status)
		r.Get("/api/usbip/exportable", usbipH.Exportable)
		r.Get("/api/usbip/sessions", usbipH.Sessions)
		r.Get("/api/usbip/sessions/{busId}", usbipH.SessionForBusID)
		r.Get("/api/usbip/policy", usbipH.Policy)
		r.Put("/api/usbip/policy", usbipH.SetPolicy)
		r.Get("/api/usbip/revocations", usbipH.RevocationsList)
		r.Get("/api/usbip/revocations/export", usbipH.RevocationsExport)
		r.Post("/api/usbip/export", usbipH.Export)
		r.Delete("/api/usbip/export", usbipH.Unexport)
		r.Post("/api/usbip/attach", usbipH.Attach)
		r.Delete("/api/usbip/attach", usbipH.Detach)

		// /api/setup/reset is destructive (clears the wizard state) so
		// it ALWAYS requires auth, regardless of cfg.Setup.Complete.
		// Lives here, inside the BearerAuth group, instead of behind
		// the SetupGate above.
		r.Post("/api/setup/reset", setupH.Reset)
	})

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	return &Server{cfg: cfg, router: r, httpServer: httpServer, usbipH: usbipH}
}

// Run starts the HTTP server and blocks until ctx is cancelled, then shuts down.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.httpServer.Addr, err)
	}

	log.Info().Str("addr", s.httpServer.Addr).Msg("HTTP server listening")

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		log.Info().Msg("HTTP server shutting down")
		s.usbipH.Stop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.Server.WriteTimeout)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("HTTP shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// allowOriginFunc builds the CORS origin predicate.
//
// Returns true when:
//
//   1. The request's Origin matches any string in the configured
//      AllowedOrigins list (exact match, scheme + host + port). This
//      is the dev-machine path: vite on :5173, Next on :3000, etc.
//
//   2. The Origin's hostname equals the hostname the request was
//      received on, regardless of port. This is the canonical
//      "panel and API on the same appliance, different ports"
//      pattern — rud1-app is served on port 80 of the Pi, this API
//      is on port 7070, and a browser pointed at http://<pi-ip>/
//      will tag XHRs to http://<pi-ip>:7070/api/* as cross-origin.
//      The pair shares trust by design, so we allow it.
//
// This is safe even with `AllowCredentials: true` because the
// browser only sends credentials when the API server explicitly
// echoes the Origin back — and we only echo origins we have
// validated above.
func allowOriginFunc(allowedOrigins []string) func(r *http.Request, origin string) bool {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[strings.ToLower(strings.TrimSpace(o))] = struct{}{}
	}
	return func(r *http.Request, origin string) bool {
		if origin == "" {
			// Same-origin requests (no Origin header). Browsers omit
			// the header for navigation; the cors lib handles this
			// upstream, but we keep the function side-effect-free.
			return false
		}
		o := strings.ToLower(origin)
		if _, ok := allowed[o]; ok {
			return true
		}
		// Same-host-any-port: parse the Origin and compare its hostname
		// to the hostname of the request we just received. r.Host can
		// include the port (e.g. "192.168.1.240:7070"), so we strip it.
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" {
			return false
		}
		reqHost := r.Host
		if h, _, splitErr := net.SplitHostPort(reqHost); splitErr == nil {
			reqHost = h
		}
		oHost := u.Hostname()
		return oHost != "" && oHost == reqHost
	}
}
