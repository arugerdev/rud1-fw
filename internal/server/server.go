// Package server wires together the Chi router, middleware, and HTTP handlers
// for the local rud1-agent API (consumed by rud1-app).
package server

import (
	"context"
	"fmt"
	"net"
	"net/http"

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
func New(
	cfg *config.Config,
	systemH *handlers.SystemHandler,
	networkH *handlers.NetworkHandler,
	vpnH *handlers.VPNHandler,
	usbH *handlers.USBHandler,
	connH *handlers.ConnectivityHandler,
) *Server {
	usbipH := handlers.NewUSBIPHandler(&cfg.USB)

	r := chi.NewRouter()

	// Global middleware — order matters.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.Server.AllowedOrigins,
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

	// Authenticated API routes.
	r.Group(func(r chi.Router) {
		r.Use(apimiddleware.BearerAuth(cfg.Server.AuthToken))

		r.Get("/api/system/info", systemH.Info)
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

		r.Get("/api/vpn/status", vpnH.Status)
		r.Post("/api/vpn/reconnect", vpnH.Reconnect)
		r.Post("/api/vpn/config", vpnH.ApplyConfig)

		r.Get("/api/usb/devices", usbH.List)

		// USB/IP server management (authorized nets only)
		r.Get("/api/usbip/status", usbipH.Status)
		r.Get("/api/usbip/exportable", usbipH.Exportable)
		r.Post("/api/usbip/export", usbipH.Export)
		r.Delete("/api/usbip/export", usbipH.Unexport)
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
