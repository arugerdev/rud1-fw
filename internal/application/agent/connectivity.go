package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
	cx "github.com/rud1-es/rud1-fw/internal/domain/connectivity"
	connimpl "github.com/rud1-es/rud1-fw/internal/infrastructure/connectivity"
	"github.com/rud1-es/rud1-fw/internal/platform"
)

// buildConnectivityService picks the right backend for the platform and
// wires the AP SSID/password from config when provided. Otherwise it falls
// back to a fixed factory default password ("configurame") and an SSID
// suffixed with the last 4 chars of the device's RegistrationCode, so two
// units in the same room don't share an SSID.
//
// Returns the Service plus a pre-configured Supervisor (nil when simulated
// or when NetworkManager is not available).
func buildConnectivityService(cfg *config.Config, registrationCode string) (cx.Service, *connimpl.Supervisor) {
	apSSID, apPass := resolveAPCredentials(cfg, registrationCode)
	persistAPPasswordHint(apSSID, apPass)

	if platform.SimulateHardware() {
		log.Info().Str("ap_ssid", apSSID).Msg("connectivity: using simulated backend")
		return connimpl.NewSimulated(apSSID, apPass), nil
	}

	nm := connimpl.NewNMBackend(connimpl.NMConfig{
		WiFiInterface: cfg.Network.WiFiInterface,
		APSSID:        apSSID,
		APPassword:    apPass,
		APInterface:   cfg.Network.APInterface,
		APCIDR:        cfg.Network.APCIDR,
		APCountry:     cfg.Network.WirelessCountry,
	})
	mm := connimpl.NewMMBackend()

	if !nm.Available() {
		log.Warn().Msg("connectivity: nmcli missing — falling back to simulated service (no real WiFi/AP control)")
		return connimpl.NewSimulated(apSSID, apPass), nil
	}

	real := connimpl.New(connimpl.Options{
		NM:        nm,
		MM:        mm,
		APSSID:    apSSID,
		APPass:    apPass,
		Preferred: cx.Preferred(cfg.Network.PreferredUplink),
	})

	var sup *connimpl.Supervisor
	if cfg.Network.AutoAP {
		grace := time.Duration(cfg.Network.OfflineGraceSeconds) * time.Second
		if grace <= 0 {
			grace = 15 * time.Second
		}
		// Closure over cfg so the wizard's POST /api/setup/complete is
		// observed on the next supervisor tick (no snapshot copy).
		isComplete := func() bool { return cfg.Setup.Complete }
		sup = connimpl.NewSupervisor(real, connimpl.SupervisorOptions{
			OfflineToAP:     grace,
			IsSetupComplete: isComplete,
		})
	}
	return real, sup
}

// DefaultAPPassword is the factory-default WPA2 passphrase the device
// broadcasts in setup mode. Kept simple and uniform across the fleet so it
// can be printed on the box / documented in the manual; the user is
// expected to change it via PUT /api/network/ap/credentials once the
// device is paired. WPA2-PSK requires 8+ chars.
const DefaultAPPassword = "configurame"

// resolveAPCredentials returns (ssid, password). Values from config take
// precedence; missing values fall back to:
//   - SSID:     "Rud1-Setup-XXXX" with the last 4 chars of the device's
//               registrationCode (so two factory-fresh units side by side
//               don't share the same SSID).
//   - Password: DefaultAPPassword ("configurame") — same on every device,
//               printed on the sticker. Operators rotate it from the panel.
func resolveAPCredentials(cfg *config.Config, registrationCode string) (string, string) {
	ssid := strings.TrimSpace(cfg.Network.APSSID)
	if ssid == "" {
		ssid = "Rud1-Setup-" + apSuffixFromCode(registrationCode)
	}

	pass := strings.TrimSpace(cfg.Network.APPassword)
	if pass == "" {
		pass = DefaultAPPassword
	}
	return ssid, pass
}

// apSuffixFromCode returns the last 4 alphanumeric chars of a
// registrationCode (which has shape "RUD1-XXXXXXXX-XXXXXXXX"), uppercased.
// Falls back to "0000" when the code is empty or shorter than 4 chars
// (e.g. a stripped-down test config) so the SSID is always well-formed.
func apSuffixFromCode(code string) string {
	stripped := strings.ReplaceAll(code, "-", "")
	if len(stripped) < 4 {
		return "0000"
	}
	return strings.ToUpper(stripped[len(stripped)-4:])
}

// persistAPPasswordHint writes SSID + password to /var/lib/rud1-agent/setup-ap.txt
// so an admin with SSH access can recover them without digging through the
// panel. Best-effort: a missing DATA_DIR is not fatal.
func persistAPPasswordHint(ssid, pass string) {
	if platform.IsWindows() {
		return
	}
	dir := "/var/lib/rud1-agent"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "setup-ap.txt"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "ssid=%s\npassword=%s\n", ssid, pass)
}
