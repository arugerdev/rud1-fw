// Package agent is the top-level application wiring.  It creates every
// infrastructure service, the HTTP server, and runs the cloud registration /
// heartbeat loops.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/domain/device"
	domainnet "github.com/rud1-es/rud1-fw/internal/domain/network"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/cloud"
	connimpl "github.com/rud1-es/rud1-fw/internal/infrastructure/connectivity"
	netscanner "github.com/rud1-es/rud1-fw/internal/infrastructure/network"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/storage"
	sysinfo "github.com/rud1-es/rud1-fw/internal/infrastructure/system"
	usblister "github.com/rud1-es/rud1-fw/internal/infrastructure/usb"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/vpn"
	"github.com/rud1-es/rud1-fw/internal/platform"
	"github.com/rud1-es/rud1-fw/internal/server"
	"github.com/rud1-es/rud1-fw/internal/server/handlers"
)

// Version is set by main via agent.Version = buildVersion before calling New.
var Version = "dev"

// Agent wires all infrastructure services together and owns the run loop.
type Agent struct {
	cfg       *config.Config
	store     *storage.DeviceStore
	identity  *device.Identity
	cloud     *cloud.Client // nil when cloud.Enabled == false
	srv       *server.Server
	connSup   *connimpl.Supervisor // nil when auto-AP disabled or in simulated mode
}

// New creates an Agent from the given Config.
func New(cfg *config.Config) (*Agent, error) {
	a := &Agent{cfg: cfg}

	// --- Storage & identity ---
	a.store = storage.NewDeviceStore()
	id, err := a.store.Load()
	if err != nil && !errors.Is(err, storage.ErrNoIdentity) {
		return nil, fmt.Errorf("load device identity: %w", err)
	}
	if errors.Is(err, storage.ErrNoIdentity) {
		regCode := cfg.Cloud.RegistrationCode
		if regCode == "" {
			regCode = generateRegistrationCode()
		}
		hostname, _ := os.Hostname()
		id = &device.Identity{
			RegistrationCode: regCode,
			SerialNumber:     machineID(),
			Hostname:         hostname,
		}
		if saveErr := a.store.Save(id); saveErr != nil {
			log.Warn().Err(saveErr).Msg("could not persist initial identity (non-fatal)")
		}
	}
	a.identity = id

	log.Info().
		Str("registration_code", a.identity.RegistrationCode).
		Str("device_id", a.identity.DeviceID).
		Str("serial_number", a.identity.SerialNumber).
		Msg("device identity loaded")

	// --- Cloud client ---
	if cfg.Cloud.Enabled {
		a.cloud = cloud.New(cfg.Cloud.BaseURL, cfg.Cloud.APISecret, cfg.Cloud.HTTPTimeout)
	}

	// --- HTTP handlers ---
	netScan := func() (*domainnet.Status, error) { return netscanner.Scan() }

	systemH := handlers.NewSystemHandler(Version, a.identity, netScan, cfg.VPN.ConfigPath, cfg.VPN.Interface)
	networkH := handlers.NewNetworkHandler(netScan)
	vpnH := handlers.NewVPNHandler(cfg.VPN.ConfigPath, cfg.VPN.Interface)
	usbH := handlers.NewUSBHandler()

	// Connectivity (WiFi / cellular / setup-AP) — picks the right backend
	// for the platform, plus an optional supervisor that auto-raises the
	// setup AP when the device has been offline too long.
	connSvc, connSup := buildConnectivityService(cfg, a.identity.SerialNumber)
	a.connSup = connSup
	connH := handlers.NewConnectivityHandler(connSvc)

	a.srv = server.New(cfg, systemH, networkH, vpnH, usbH, connH)

	return a, nil
}

// Run starts the HTTP server and cloud loops, blocking until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	srvErr := make(chan error, 1)
	go func() {
		if err := a.srv.Run(ctx); err != nil {
			srvErr <- err
		}
	}()

	if a.connSup != nil {
		go a.connSup.Run(ctx)
	}

	if a.cfg.Cloud.Enabled && a.cloud != nil {
		if a.identity.DeviceID == "" {
			go a.registrationLoop(ctx)
		} else {
			go a.heartbeatLoop(ctx)
			go a.firmwareLoop(ctx)
		}
	}

	select {
	case err := <-srvErr:
		return fmt.Errorf("server: %w", err)
	case <-ctx.Done():
		log.Info().Msg("agent context cancelled — shutting down")
		return nil
	}
}

// registrationLoop retries device registration every 30 s until it succeeds.
func (a *Agent) registrationLoop(ctx context.Context) {
	log.Info().
		Str("registration_code", a.identity.RegistrationCode).
		Msg("waiting for registration — enter this code in rud1-es dashboard")

	hostname, _ := os.Hostname()
	req := cloud.RegisterRequest{
		RegistrationCode: a.identity.RegistrationCode,
		SerialNumber:     a.identity.SerialNumber,
		FirmwareVersion:  Version,
		Platform:         platform.OS(),
		Arch:             platform.Arch(),
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		resp, err := a.cloud.Register(ctx, req)
		if err == nil {
			a.identity.DeviceID = resp.DeviceID
			a.identity.Hostname = hostname
			a.identity.RegisteredAt = time.Now()
			// Use serialNumber from ES DB (may differ from machineID if device
			// was pre-created in the dashboard with its own serial).
			if resp.SerialNumber != "" {
				a.identity.SerialNumber = resp.SerialNumber
			}

			if saveErr := a.store.Save(a.identity); saveErr != nil {
				log.Error().Err(saveErr).Msg("failed to persist registration")
			}
			log.Info().
				Str("device_id", resp.DeviceID).
				Msg("device registered successfully")

			go a.heartbeatLoop(ctx)
			go a.firmwareLoop(ctx)
			return
		}

		// 409 = already provisioned — can happen on restart after partial save.
		if strings.Contains(err.Error(), "already provisioned") {
			log.Warn().Msg("device already provisioned in cloud — sending heartbeat anyway")
			go a.heartbeatLoop(ctx)
			go a.firmwareLoop(ctx)
			return
		}

		log.Warn().Err(err).Msg("registration attempt failed — retrying in 30 s")
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// heartbeatLoop sends a heartbeat on every HeartbeatInterval tick.
func (a *Agent) heartbeatLoop(ctx context.Context) {
	log.Info().
		Str("registration_code", a.identity.RegistrationCode).
		Dur("interval", a.cfg.Cloud.HeartbeatInterval).
		Msg("starting heartbeat loop")

	// Send one immediately, then tick.
	a.sendHeartbeat(ctx)

	ticker := time.NewTicker(a.cfg.Cloud.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sendHeartbeat(ctx)
		}
	}
}

func (a *Agent) sendHeartbeat(ctx context.Context) {
	metrics, err := sysinfo.Read()
	if err != nil {
		log.Warn().Err(err).Msg("heartbeat: failed to read system metrics")
		metrics = &sysinfo.Metrics{}
	}

	hostname, _ := os.Hostname()
	kernelVer := sysinfo.KernelVersion()

	// ── Info ──────────────────────────────────────────────────────────────
	info := &cloud.HBInfo{
		Hostname:      hostname,
		AgentVersion:  Version,
		Platform:      platform.OS(),
		Arch:          platform.Arch(),
		Simulated:     platform.SimulateHardware(),
		KernelVersion: kernelVer,
		UptimeSeconds: metrics.Uptime,
	}

	// ── Metrics ───────────────────────────────────────────────────────────
	hbMetrics := &cloud.HBMetrics{
		CPUUsage:    metrics.CPUUsage,
		MemoryUsage: metrics.MemoryUsage,
		Uptime:      metrics.Uptime,
	}
	if metrics.Temperature > 0 {
		v := metrics.Temperature
		hbMetrics.Temperature = &v
	}
	if metrics.DiskUsage > 0 {
		v := metrics.DiskUsage
		hbMetrics.DiskUsage = &v
	}
	if metrics.RxBytes > 0 {
		v := metrics.RxBytes
		hbMetrics.RxBytes = &v
	}
	if metrics.TxBytes > 0 {
		v := metrics.TxBytes
		hbMetrics.TxBytes = &v
	}

	// ── Network ───────────────────────────────────────────────────────────
	netSt, _ := netscanner.Scan()
	var hbNetwork *cloud.HBNetwork
	if netSt != nil {
		ifaces := make([]cloud.HBNetworkInterface, 0, len(netSt.Interfaces))
		for _, iface := range netSt.Interfaces {
			ipv4 := iface.IPv4
			if ipv4 == nil {
				ipv4 = []string{}
			}
			ipv6 := iface.IPv6
			if ipv6 == nil {
				ipv6 = []string{}
			}
			ifaces = append(ifaces, cloud.HBNetworkInterface{
				Name:       iface.Name,
				MAC:        iface.MAC,
				MTU:        iface.MTU,
				Up:         iface.Up,
				IPv4:       ipv4,
				IPv6:       ipv6,
				IsLoopback: iface.IsLoopback,
				IsWireless: iface.IsWireless,
			})
		}
		dns := netSt.DNS
		if dns == nil {
			dns = []string{}
		}
		hbNetwork = &cloud.HBNetwork{
			Hostname:   netSt.Hostname,
			Interfaces: ifaces,
			Gateway:    netSt.Gateway,
			DNS:        dns,
			Internet:   netSt.Internet,
		}
	}

	// ── VPN ───────────────────────────────────────────────────────────────
	// Only include the VPN section when the config file exists and contains
	// a peer public key (required by the ES schema).
	var hbVPN *cloud.HBVPN
	if a.cfg.VPN.ConfigPath != "" {
		if st, err := wireguard.Read(a.cfg.VPN.ConfigPath); err == nil && st.PublicKey != "" {
			hbVPN = &cloud.HBVPN{
				InterfaceName: st.Interface,
				PublicKey:     st.PublicKey,
				Connected:     st.Connected,
				Endpoint:      st.Endpoint,
				AllowedIps:    st.AllowedIPs,
				DNS:           st.DNS,
				PeerCount:     1,
			}
		}
	}

	// ── USB + USB/IP ──────────────────────────────────────────────────────
	usbDevs, _ := usblister.List()
	usbipSrv := usblister.NewUSBIPServer(a.cfg.USB.BindPort)
	exportedIDs := usbipSrv.ExportedDevices()

	var hbUSB *cloud.HBUSB
	if len(usbDevs) > 0 || a.cfg.USB.USBIPEnabled {
		devices := make([]cloud.HBUSBDevice, 0, len(usbDevs))
		exportedSet := make(map[string]bool, len(exportedIDs))
		for _, id := range exportedIDs {
			exportedSet[id] = true
		}
		for _, d := range usbDevs {
			dev := cloud.HBUSBDevice{
				BusID:     d.BusID,
				VendorID:  d.VendorID,
				ProductID: d.ProductID,
				Shared:    exportedSet[d.BusID],
			}
			if d.VendorName != "" {
				s := d.VendorName
				dev.VendorName = &s
			}
			if d.ProductName != "" {
				s := d.ProductName
				dev.ProductName = &s
			}
			if d.Serial != "" {
				s := d.Serial
				dev.Serial = &s
			}
			devices = append(devices, dev)
		}
		hbUSB = &cloud.HBUSB{
			Devices:        devices,
			UsbipEnabled:   a.cfg.USB.USBIPEnabled,
			ExportedBusIDs: exportedIDs,
		}
	}

	payload := cloud.HeartbeatPayload{
		RegistrationCode: a.identity.RegistrationCode,
		SerialNumber:     a.identity.SerialNumber,
		FirmwareVersion:  Version,
		Info:             info,
		Metrics:          hbMetrics,
		Network:          hbNetwork,
		VPN:              hbVPN,
		USB:              hbUSB,
	}

	if _, err := a.cloud.Heartbeat(ctx, payload); err != nil {
		log.Warn().Err(err).Msg("heartbeat send failed")
	} else {
		log.Debug().Msg("heartbeat sent")
	}
}

// firmwareLoop checks for firmware updates every 10 minutes.
func (a *Agent) firmwareLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.checkAndApplyFirmware(ctx)
		}
	}
}

func (a *Agent) checkAndApplyFirmware(ctx context.Context) {
	pending, err := a.cloud.CheckFirmware(ctx, a.identity.RegistrationCode)
	if err != nil {
		log.Warn().Err(err).Msg("firmware check failed")
		return
	}
	if pending == nil {
		log.Debug().Msg("firmware: no update available")
		return
	}

	log.Info().
		Str("version", pending.Version).
		Str("sha256", pending.SHA256).
		Msg("firmware update available — downloading")

	// Download the firmware binary.
	dlReq, err := http.NewRequestWithContext(ctx, http.MethodGet, pending.URL, nil)
	if err != nil {
		log.Error().Err(err).Msg("firmware: build download request failed")
		_ = a.cloud.AckFirmware(ctx, pending.RolloutID, a.identity.RegistrationCode, "FAILED", err.Error())
		return
	}
	dlReq.Header.Set("Authorization", "Bearer "+a.cfg.Cloud.APISecret)

	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(dlReq)
	if err != nil {
		log.Error().Err(err).Msg("firmware: download failed")
		_ = a.cloud.AckFirmware(ctx, pending.RolloutID, a.identity.RegistrationCode, "FAILED", err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("download returned status %d", resp.StatusCode)
		log.Error().Int("status", resp.StatusCode).Msg("firmware: " + msg)
		_ = a.cloud.AckFirmware(ctx, pending.RolloutID, a.identity.RegistrationCode, "FAILED", msg)
		return
	}

	// Write to a temp file and verify checksum.
	tmp, err := os.CreateTemp("", "rud1-fw-*.bin")
	if err != nil {
		log.Error().Err(err).Msg("firmware: create temp file failed")
		return
	}
	defer os.Remove(tmp.Name())

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
		log.Error().Err(err).Msg("firmware: write temp file failed")
		tmp.Close()
		_ = a.cloud.AckFirmware(ctx, pending.RolloutID, a.identity.RegistrationCode, "FAILED", err.Error())
		return
	}
	tmp.Close()

	got := hex.EncodeToString(h.Sum(nil))
	if got != pending.SHA256 {
		msg := fmt.Sprintf("SHA256 mismatch: expected %s got %s", pending.SHA256, got)
		log.Error().Msg("firmware: " + msg)
		_ = a.cloud.AckFirmware(ctx, pending.RolloutID, a.identity.RegistrationCode, "FAILED", msg)
		return
	}

	log.Info().Str("version", pending.Version).Msg("firmware: checksum verified — installing")

	if platform.SimulateHardware() {
		log.Info().Msg("firmware: simulated install (no-op on dev)")
		_ = a.cloud.AckFirmware(ctx, pending.RolloutID, a.identity.RegistrationCode, "COMPLETED", "")
		return
	}

	// Replace the running executable.
	exe, err := os.Executable()
	if err != nil {
		log.Error().Err(err).Msg("firmware: cannot determine executable path")
		_ = a.cloud.AckFirmware(ctx, pending.RolloutID, a.identity.RegistrationCode, "FAILED", err.Error())
		return
	}

	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		log.Error().Err(err).Msg("firmware: chmod failed")
		_ = a.cloud.AckFirmware(ctx, pending.RolloutID, a.identity.RegistrationCode, "FAILED", err.Error())
		return
	}

	// Atomic rename: temp → exe.new → exe.
	newExe := exe + ".new"
	if err := os.Rename(tmp.Name(), newExe); err != nil {
		log.Error().Err(err).Msg("firmware: rename to .new failed")
		_ = a.cloud.AckFirmware(ctx, pending.RolloutID, a.identity.RegistrationCode, "FAILED", err.Error())
		return
	}
	if err := os.Rename(newExe, exe); err != nil {
		log.Error().Err(err).Msg("firmware: replace executable failed")
		_ = a.cloud.AckFirmware(ctx, pending.RolloutID, a.identity.RegistrationCode, "FAILED", err.Error())
		return
	}

	// Ack before restarting so the cloud marks the rollout completed.
	_ = a.cloud.AckFirmware(ctx, pending.RolloutID, a.identity.RegistrationCode, "COMPLETED", "")
	log.Info().Str("version", pending.Version).Msg("firmware installed — restarting agent")

	// Spawn the new binary then exit.
	// On Linux with systemd Restart=always the unit will also restart cleanly.
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		log.Error().Err(err).Msg("firmware: restart failed — manual restart required")
		return
	}
	os.Exit(0)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func generateRegistrationCode() string {
	return fmt.Sprintf("RUD1-%s-%s", randomHex(4), randomHex(4))
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return strings.ToUpper(hex.EncodeToString(b))
}

// machineID reads the Linux machine-id. Falls back to hostname.
func machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	h, _ := os.Hostname()
	return h
}

func firstNonLoopbackIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return ""
}
