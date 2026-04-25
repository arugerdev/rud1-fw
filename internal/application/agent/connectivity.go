package agent

import (
	"crypto/sha256"
	"encoding/hex"
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
// wires the AP SSID/password, pulling them from config when provided or
// deriving deterministic defaults from the device's machine-id otherwise.
//
// Returns the Service plus a pre-configured Supervisor (nil when simulated
// or when NetworkManager is not available).
func buildConnectivityService(cfg *config.Config, machineID string) (cx.Service, *connimpl.Supervisor) {
	apSSID, apPass := resolveAPCredentials(cfg, machineID)
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

// resolveAPCredentials returns (ssid, password). Either value from config
// takes precedence; missing values are derived deterministically from the
// machine-id so the credentials are stable across reboots but unique per
// device.
func resolveAPCredentials(cfg *config.Config, machineID string) (string, string) {
	sum := sha256.Sum256([]byte(machineID))
	hexSum := hex.EncodeToString(sum[:])

	ssid := strings.TrimSpace(cfg.Network.APSSID)
	if ssid == "" {
		suffix := strings.ToUpper(hexSum[:4])
		ssid = "Rud1-Setup-" + suffix
	}

	pass := strings.TrimSpace(cfg.Network.APPassword)
	if pass == "" {
		// 12 hex chars = 48 bits of entropy; WPA2-PSK requires 8+ chars.
		pass = hexSum[4:16]
	}
	return ssid, pass
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
