package agent

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/server/handlers"

	wireguard "github.com/rud1-es/rud1-fw/internal/infrastructure/vpn"
)

// buildSetupHealthCheckers wires the four user-facing checks the wizard
// surfaces: internet, VPN, cloud, USB/IP. All checkers are invoked with a
// short per-check budget by the handler, so each implementation can do
// best-effort work without worrying about hanging the whole response.
//
// Wording is intentionally Spanish + non-technical because the panel
// renders these strings directly to the installer. Don't add stack
// traces or stderr dumps — operators expect "ok" or a one-line hint.
func buildSetupHealthCheckers(a *Agent, cfg *config.Config) []handlers.SetupHealthChecker {
	return []handlers.SetupHealthChecker{
		// Internet — same primitive the connectivity supervisor uses
		// (TCP dial to two well-known recursive DNS resolvers).
		func(ctx context.Context) handlers.SetupHealthCheck {
			ok := probeInternet(ctx)
			detail := "Conexión saliente disponible"
			if !ok {
				detail = "Sin conexión a internet — comprueba WiFi o red móvil"
			}
			return handlers.SetupHealthCheck{
				ID:     "internet",
				Label:  "Conexión a internet",
				Ok:     ok,
				Detail: detail,
			}
		},

		// VPN — fresh handshake on the WG interface means at least one
		// peer is up. Zero handshake (server with zero connected peers,
		// or fresh device) is reported as "pending" rather than failure
		// so the wizard doesn't scare the operator pre-claim.
		func(_ context.Context) handlers.SetupHealthCheck {
			iface := cfg.VPN.Interface
			if iface == "" {
				return handlers.SetupHealthCheck{
					ID:     "vpn",
					Label:  "Túnel WireGuard",
					Ok:     false,
					Detail: "no disponible",
				}
			}
			ts, err := wireguard.LatestHandshake(iface)
			if err != nil {
				return handlers.SetupHealthCheck{
					ID:     "vpn",
					Label:  "Túnel WireGuard",
					Ok:     false,
					Detail: "Servicio WireGuard no disponible (instálalo o revisa wg-quick)",
				}
			}
			if ts.IsZero() {
				return handlers.SetupHealthCheck{
					ID:     "vpn",
					Label:  "Túnel WireGuard",
					Ok:     false,
					Detail: "Pendiente: sin clientes conectados todavía",
				}
			}
			age := time.Since(ts).Round(time.Second)
			return handlers.SetupHealthCheck{
				ID:     "vpn",
				Label:  "Túnel WireGuard",
				Ok:     age < 3*time.Minute,
				Detail: fmt.Sprintf("Último handshake hace %s", age),
			}
		},

		// Cloud — TCP-reachability to rud1.es (or whatever BaseURL the
		// operator pinned). We don't issue a heartbeat from here because
		// /api/setup/health may run unauthenticated; the heartbeat loop
		// owns the real telemetry path.
		func(ctx context.Context) handlers.SetupHealthCheck {
			if !cfg.Cloud.Enabled {
				return handlers.SetupHealthCheck{
					ID:     "cloud",
					Label:  "Conexión a rud1.es",
					Ok:     false,
					Detail: "Cloud deshabilitado en config",
				}
			}
			host := hostFromBaseURL(cfg.Cloud.BaseURL)
			if host == "" {
				return handlers.SetupHealthCheck{
					ID:     "cloud",
					Label:  "Conexión a rud1.es",
					Ok:     false,
					Detail: "URL del servicio en la nube no es válida",
				}
			}
			if !probeTCP(ctx, net.JoinHostPort(host, "443"), 2*time.Second) {
				return handlers.SetupHealthCheck{
					ID:     "cloud",
					Label:  "Conexión a rud1.es",
					Ok:     false,
					Detail: "No se puede contactar con " + host + ":443",
				}
			}
			// Identified as paired? — DeviceID is set after the first
			// successful claim heartbeat.
			if a != nil && a.identity != nil && a.identity.DeviceID == "" {
				return handlers.SetupHealthCheck{
					ID:     "cloud",
					Label:  "Conexión a rud1.es",
					Ok:     false,
					Detail: "Pendiente de emparejamiento desde el panel rud1.es",
				}
			}
			return handlers.SetupHealthCheck{
				ID:     "cloud",
				Label:  "Conexión a rud1.es",
				Ok:     true,
				Detail: "Dispositivo emparejado y alcanzando " + host,
			}
		},

		// USB/IP — the kernel server is either up (Linux + module loaded)
		// or it isn't. We surface that state as the truth. A device that
		// doesn't intend to share USB still gets ok=false here with a
		// "deshabilitado" hint; the wizard treats that as a soft fail.
		func(_ context.Context) handlers.SetupHealthCheck {
			if a == nil || a.usbipH == nil {
				return handlers.SetupHealthCheck{
					ID:     "usbip",
					Label:  "Servidor USB/IP",
					Ok:     false,
					Detail: "no disponible",
				}
			}
			if !cfg.USB.USBIPEnabled {
				return handlers.SetupHealthCheck{
					ID:     "usbip",
					Label:  "Servidor USB/IP",
					Ok:     false,
					Detail: "Deshabilitado en config (usb.usbip_enabled=false)",
				}
			}
			exported := a.usbipH.Server().ExportedDevices()
			return handlers.SetupHealthCheck{
				ID:     "usbip",
				Label:  "Servidor USB/IP",
				Ok:     true,
				Detail: fmt.Sprintf("Servicio activo, %d dispositivos exportados", len(exported)),
			}
		},
	}
}

// hostFromBaseURL strips scheme/path from a BaseURL like "https://rud1.es"
// so we can issue a bare TCP probe. Empty / malformed input returns "".
func hostFromBaseURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Host == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err == nil {
		return host
	}
	return u.Host
}

// probeTCP dials addr with a deadline. Mirrors the connectivity package's
// helper but takes a context so the handler's per-check budget is honored.
func probeTCP(ctx context.Context, addr string, fallback time.Duration) bool {
	d := net.Dialer{}
	if fallback > 0 {
		d.Timeout = fallback
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// probeInternet mirrors connectivity.defaultInternetProbe so the wizard's
// internet check matches what the supervisor uses to decide AP raise/drop.
func probeInternet(ctx context.Context) bool {
	return probeTCP(ctx, "8.8.8.8:53", 2*time.Second) || probeTCP(ctx, "1.1.1.1:53", 2*time.Second)
}
