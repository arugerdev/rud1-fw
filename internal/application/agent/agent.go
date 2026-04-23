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
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/domain/device"
	domainnet "github.com/rud1-es/rud1-fw/internal/domain/network"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/bootidentity"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/cloud"
	connimpl "github.com/rud1-es/rud1-fw/internal/infrastructure/connectivity"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/lan"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/nat"
	netscanner "github.com/rud1-es/rud1-fw/internal/infrastructure/network"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/storage"
	sysinfo "github.com/rud1-es/rud1-fw/internal/infrastructure/system"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/sysstat"
	usblister "github.com/rud1-es/rud1-fw/internal/infrastructure/usb"
	wireguard "github.com/rud1-es/rud1-fw/internal/infrastructure/vpn"
	"github.com/rud1-es/rud1-fw/internal/platform"
	"github.com/rud1-es/rud1-fw/internal/server"
	"github.com/rud1-es/rud1-fw/internal/server/handlers"
)

// Version is set by main via agent.Version = buildVersion before calling New.
var Version = "dev"

// Agent wires all infrastructure services together and owns the run loop.
type Agent struct {
	cfg      *config.Config
	store    *storage.DeviceStore
	identity *device.Identity
	boot     bootidentity.Identity // immutable code+pin from /boot
	cloud    *cloud.Client         // nil when cloud.Enabled == false
	srv      *server.Server
	usbipH   *handlers.USBIPHandler // shared with heartbeat loop so ExportedDevices() matches sysfs
	lanMgr   *lan.Manager           // owns the LAN-routing iptables rules
	connSup  *connimpl.Supervisor   // nil when auto-AP disabled or in simulated mode
	sysstats *sysstat.Collector     // shared between HTTP handler + heartbeat loop

	// WireGuard SERVER identity — generated at first boot, persisted under
	// /var/lib/rud1-agent and mirrored (public half only) for the heartbeat.
	wgPubkey string

	// NAT discovery cache. Populated by `natDiscoveryLoop` every ~20 min and
	// read by every heartbeat. Guarded by `natMu` because the loop writes
	// from its own goroutine.
	natMu    sync.RWMutex
	natState nat.Discovery

	lastAppliedSubnet string // cache: which subnet we last materialised in wg0.conf
}

// New creates an Agent from the given Config.
func New(cfg *config.Config) (*Agent, error) {
	a := &Agent{cfg: cfg}

	// --- Boot identity (immutable code+pin) ---
	// Loaded once from /boot/rud1-identity.json (or generated if missing).
	// This is the source of truth for RegistrationCode/Pin — the runtime
	// storage below just caches hostname and post-claim DeviceID.
	bootID, err := bootidentity.EnsureIdentity(platform.BootIdentityPath())
	if err != nil {
		return nil, fmt.Errorf("ensure boot identity: %w", err)
	}
	a.boot = bootID

	// --- Runtime identity (hostname + post-claim device_id cache) ---
	a.store = storage.NewDeviceStore()
	id, err := a.store.Load()
	if err != nil && !errors.Is(err, storage.ErrNoIdentity) {
		return nil, fmt.Errorf("load device identity: %w", err)
	}
	if errors.Is(err, storage.ErrNoIdentity) {
		hostname, _ := os.Hostname()
		id = &device.Identity{
			RegistrationCode: bootID.RegistrationCode,
			RegistrationPin:  bootID.RegistrationPin,
			SerialNumber:     machineID(),
			Hostname:         hostname,
		}
		if saveErr := a.store.Save(id); saveErr != nil {
			log.Warn().Err(saveErr).Msg("could not persist initial identity (non-fatal)")
		}
	} else {
		// Sync cached identity with the authoritative /boot file in case it
		// was rotated out-of-band (factory reset flow).
		if id.RegistrationCode != bootID.RegistrationCode ||
			id.RegistrationPin != bootID.RegistrationPin {
			id.RegistrationCode = bootID.RegistrationCode
			id.RegistrationPin = bootID.RegistrationPin
			id.DeviceID = "" // force re-claim if the boot identity changed
			_ = a.store.Save(id)
		}
	}
	a.identity = id

	log.Info().
		Str("registration_code", a.identity.RegistrationCode).
		Str("device_id", a.identity.DeviceID).
		Str("serial_number", a.identity.SerialNumber).
		Msg("device identity loaded")

	// --- WireGuard SERVER identity + config (no hub — each Pi is its own) ---
	//
	// The server subnet is computed deterministically from the registration
	// code: clients never rewire their routing when a Pi reinstalls the
	// same identity. The listen port is the DefaultListenPort from the
	// wireguard package (51820).
	privkeyPath := cfg.VPN.PrivateKeyPath
	if privkeyPath == "" {
		privkeyPath = filepath.Join(platform.DataDir(), "wg-server.key")
	}
	pubkeyPath := cfg.VPN.PubkeyPath
	if pubkeyPath == "" {
		pubkeyPath = filepath.Join(platform.DataDir(), "wg-server.pub")
	}
	wgPub, err := wireguard.EnsureKeypair(privkeyPath, pubkeyPath)
	if err != nil {
		return nil, fmt.Errorf("ensure wg keypair: %w", err)
	}
	a.wgPubkey = wgPub

	subnet := deriveSubnet(a.identity.RegistrationCode)
	serverCIDR := subnet + ".1/24"
	if err := a.writeServerConfigIfNeeded(privkeyPath, serverCIDR); err != nil {
		// Non-fatal: the device still runs, heartbeats still flow, the
		// cloud surfaces the error in endpointReady=false.
		log.Warn().Err(err).Msg("wireguard: server config write failed")
	}
	a.lastAppliedSubnet = serverCIDR

	// --- Cloud client ---
	if cfg.Cloud.Enabled {
		a.cloud = cloud.New(cfg.Cloud.BaseURL, cfg.Cloud.APISecret, cfg.Cloud.HTTPTimeout)
	}

	// --- HTTP handlers ---
	netScan := func() (*domainnet.Status, error) { return netscanner.Scan() }

	systemH := handlers.NewSystemHandler(Version, a.identity, netScan, cfg.VPN.ConfigPath, cfg.VPN.Interface)
	networkH := handlers.NewNetworkHandler(netScan)
	vpnH := handlers.NewVPNHandler(
		cfg.VPN.ConfigPath,
		cfg.VPN.Interface,
		cfg.VPN.PubkeyPath,
		a.snapshotNAT,
	)
	vpnPeerH := handlers.NewVPNPeerHandler(cfg.VPN.Interface)
	usbH := handlers.NewUSBHandler()
	usbipH := handlers.NewUSBIPHandler(cfg)
	a.usbipH = usbipH
	identityH := handlers.NewIdentityHandler(bootID)

	// LAN routing manager — source subnet is the Pi's own /24 so WG peers
	// reaching LAN targets get correctly NAT'd out the uplink. We detect
	// the uplink interface here so the user doesn't have to edit yaml by
	// hand on non-standard hardware.
	lanMgr := lan.NewManager()
	uplink := cfg.LAN.UplinkInterface
	if strings.TrimSpace(uplink) == "" {
		uplink = lan.DetectDefaultUplink()
	}
	lanMgr.Configure(deriveSubnet(a.identity.RegistrationCode)+".0/24", uplink)
	a.lanMgr = lanMgr
	lanH := handlers.NewLANHandler(cfg, lanMgr)
	// Reachability probe lives next to the routes API so the UI can
	// sanity-check a target before asking the operator to expose it.
	lanProbeH := handlers.NewLANProbeHandler(&lan.Prober{})
	lanTraceH := handlers.NewLANTracerouteHandler(&lan.Tracer{})
	// Seed the kernel with the persisted desired set so a reboot re-installs
	// any rules the operator had enabled before.
	if cfg.LAN.Enabled && len(cfg.LAN.Routes) > 0 {
		if _, errs := lanMgr.Apply(cfg.LAN.Routes); len(errs) > 0 {
			for _, err := range errs {
				log.Warn().Err(err).Msg("lan: initial apply error")
			}
		}
	}

	// Connectivity (WiFi / cellular / setup-AP) — picks the right backend
	// for the platform, plus an optional supervisor that auto-raises the
	// setup AP when the device has been offline too long.
	connSvc, connSup := buildConnectivityService(cfg, a.identity.SerialNumber)
	a.connSup = connSup
	connH := handlers.NewConnectivityHandler(connSvc)

	// System stats collector — shared between the HTTP handler (/api/system/stats)
	// and the heartbeat loop (HBSystem block). Stateless apart from the optional
	// Uplink hint, so a single instance is safe to reuse concurrently.
	a.sysstats = &sysstat.Collector{Uplink: lan.DetectDefaultUplink()}
	sysStatsH := handlers.NewSystemStatsHandler(a.sysstats)

	a.srv = server.New(cfg, systemH, networkH, vpnH, vpnPeerH, usbH, usbipH, connH, identityH, lanH, lanProbeH, lanTraceH, sysStatsH)

	return a, nil
}

// deriveSubnet turns a registration code into the "10.77.N" prefix of the
// device's /24 (matches rud1-es/deviceSubnetFor exactly). We do it locally
// to avoid a chicken-and-egg dependency on the cloud before first claim.
func deriveSubnet(registrationCode string) string {
	h := sha256.Sum256([]byte(registrationCode))
	bucket := int(h[0])%254 + 1
	return fmt.Sprintf("10.77.%d", bucket)
}

// writeServerConfigIfNeeded materialises wg0.conf as a SERVER config the
// first time (or after the subnet changed due to an identity rotation).
// Restarts wg-quick@<iface> to activate. No-op on simulated hardware.
func (a *Agent) writeServerConfigIfNeeded(privkeyPath, addressCIDR string) error {
	privkey, err := wireguard.ReadPrivateKey(privkeyPath)
	if err != nil {
		return err
	}
	spec := wireguard.ServerSpec{
		Interface:   a.cfg.VPN.Interface,
		PrivateKey:  privkey,
		AddressCIDR: addressCIDR,
		ListenPort:  wireguard.DefaultListenPort,
	}
	if err := wireguard.WriteServerConfig(a.cfg.VPN.ConfigPath, spec); err != nil {
		return err
	}
	if err := wireguard.RestartServer(a.cfg.VPN.Interface); err != nil {
		return fmt.Errorf("wg-quick restart: %w", err)
	}
	log.Info().
		Str("interface", a.cfg.VPN.Interface).
		Str("address", addressCIDR).
		Int("listen_port", wireguard.DefaultListenPort).
		Msg("wireguard: server config applied")
	return nil
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

	// Start the rolling-window sampler for CPU% / LoadAvg1 percentiles
	// so /api/system/stats?percentiles=1 has data as soon as the API is
	// reachable. Idempotent via sync.Once — safe even if Run ever gets
	// re-entered by supervisor glue.
	if a.sysstats != nil {
		a.sysstats.Start(ctx)
	}

	// NAT discovery runs independently of cloud connectivity so the
	// heartbeat has fresh data on its first tick.
	go a.natDiscoveryLoop(ctx)

	if a.cfg.Cloud.Enabled && a.cloud != nil {
		// Single loop in the no-hub world: every heartbeat is both a
		// "registration/claim" nudge (if not yet claimed) and a normal
		// telemetry push (once claimed). The cloud discriminates via the
		// `status` field.
		go a.heartbeatLoop(ctx)
		go a.firmwareLoop(ctx)
	}

	// Independent of cloud connectivity: keep the exported USB/IP set in
	// sync with the active policy. Catches the case where a remote client
	// detached (status 3→0) without the operator issuing an explicit PUT
	// and the current policy has since diverged from what was allowed at
	// bind time.
	go a.policySweepLoop(ctx)

	select {
	case err := <-srvErr:
		return fmt.Errorf("server: %w", err)
	case <-ctx.Done():
		log.Info().Msg("agent context cancelled — shutting down")
		return nil
	}
}

// natDiscoveryInterval controls how often we re-run Discover. 20 min is a
// compromise: short enough that a router reboot recovers its port mapping
// within one cycle; long enough to avoid STUN spam across the fleet.
const natDiscoveryInterval = 20 * time.Minute

// natDiscoveryLoop keeps `natState` fresh. First discovery runs immediately
// so the first heartbeat has populated fields.
func (a *Agent) natDiscoveryLoop(ctx context.Context) {
	a.refreshNAT(ctx)
	ticker := time.NewTicker(natDiscoveryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.refreshNAT(ctx)
		}
	}
}

// refreshNAT discovers the current public endpoint (UPnP → STUN) and caches
// it under natMu. Failures leave the previous cache in place so a flaky
// STUN server doesn't temporarily wipe a good endpoint.
func (a *Agent) refreshNAT(ctx context.Context) {
	d := nat.Discover(ctx, wireguard.DefaultListenPort)
	a.natMu.Lock()
	if d.PublicEndpoint != "" || a.natState.PublicEndpoint == "" {
		// Accept the new discovery if it yielded a result OR if we had
		// nothing cached. Never overwrite a good endpoint with empty.
		a.natState = d
	}
	a.natMu.Unlock()
	log.Info().
		Str("endpoint", d.PublicEndpoint).
		Bool("upnp_ok", d.UPnPOK).
		Str("nat_type", d.NATType).
		Str("source", d.Source).
		Msg("nat: discovery complete")
}

// snapshotNAT returns the latest cached discovery under read-lock.
func (a *Agent) snapshotNAT() nat.Discovery {
	a.natMu.RLock()
	defer a.natMu.RUnlock()
	return a.natState
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
	// In the no-hub model, the `publicKey` we advertise is this device's own
	// WG SERVER pubkey — rud1-es writes it verbatim as the `[Peer]
	// PublicKey` in client .conf files.
	var hbVPN *cloud.HBVPN
	ownPubkey := a.wgPubkey
	if ownPubkey == "" && a.cfg.VPN.PubkeyPath != "" {
		if key, err := wireguard.ReadOwnPubkey(a.cfg.VPN.PubkeyPath); err == nil {
			ownPubkey = key
		}
	}
	if ownPubkey != "" {
		iface := a.cfg.VPN.Interface
		connected := wireguard.IsConnected(iface)
		natSnap := a.snapshotNAT()
		peerCount := 0
		var lastHandshakePtr *string
		if ts, err := wireguard.LatestHandshake(iface); err == nil && !ts.IsZero() {
			hs := ts.UTC().Format(time.RFC3339)
			lastHandshakePtr = &hs
		}
		var peerTelemetry []cloud.HBVPNPeerTelemetry
		activePeers := 0
		if peers, err := wireguard.ListPeers(iface); err == nil {
			peerCount = len(peers)
			freshCutoff := time.Now().Add(-3 * time.Minute)
			peerTelemetry = make([]cloud.HBVPNPeerTelemetry, 0, len(peers))
			for _, p := range peers {
				row := cloud.HBVPNPeerTelemetry{
					PublicKey: p.PublicKey,
					Endpoint:  p.Endpoint,
					BytesRx:   p.BytesRx,
					BytesTx:   p.BytesTx,
				}
				if !p.LatestHshake.IsZero() {
					row.LastHandshake = p.LatestHshake.UTC().Format(time.RFC3339)
					if p.LatestHshake.After(freshCutoff) {
						activePeers++
					}
				}
				peerTelemetry = append(peerTelemetry, row)
			}
		}
		upnpOK := natSnap.UPnPOK
		hbVPN = &cloud.HBVPN{
			InterfaceName:  iface,
			PublicKey:      ownPubkey,
			Address:        a.lastAppliedSubnet,
			Connected:      connected,
			Endpoint:       natSnap.PublicEndpoint,
			PublicEndpoint: natSnap.PublicEndpoint,
			UPnPOK:         &upnpOK,
			NATType:        natSnap.NATType,
			AllowedIps:     deriveSubnet(a.identity.RegistrationCode) + ".0/24",
			PeerCount:      peerCount,
			ActivePeers:    activePeers,
			LastHandshake:  lastHandshakePtr,
			PeerTelemetry:  peerTelemetry,
		}
	}

	// ── USB + USB/IP ──────────────────────────────────────────────────────
	// Share the USBIPServer instance owned by the HTTP handler so
	// ExportedDevices() reflects actual bind state (a fresh instance would
	// always report empty).
	usbDevs, _ := usblister.List()
	exportedIDs := a.usbipH.Server().ExportedDevices()

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

		// Read kernel usbip_status per device to tell the cloud which
		// shared devices have an active remote client attached. On
		// non-Linux platforms this returns nil/empty and the field is
		// omitted from the heartbeat.
		var inUse []string
		if sessions, err := usblister.ListSessions(); err == nil {
			for _, s := range sessions {
				if s.Attached {
					inUse = append(inUse, s.BusID)
				}
			}
		}

		hbUSB = &cloud.HBUSB{
			Devices:        devices,
			UsbipEnabled:   a.cfg.USB.USBIPEnabled,
			ExportedBusIDs: exportedIDs,
			InUseBusIDs:    inUse,
		}
	}

	// ── LAN ────────────────────────────────────────────────────────────────
	// Echo the user's chosen LAN-exposure rules to the cloud so rud1-es can
	// widen each user peer's AllowedIPs to include them. Only populated when
	// LAN is enabled; a disabled LAN field stays nil so the cloud can tell
	// the difference between "not configured" and "explicitly off".
	var hbLAN *cloud.HBLAN
	if a.lanMgr != nil && a.cfg.LAN.Enabled {
		live := a.lanMgr.Snapshot()
		routes := make([]cloud.HBLANRoute, 0, len(live))
		for _, r := range live {
			routes = append(routes, cloud.HBLANRoute{Subnet: r.TargetSubnet, Applied: r.Applied})
		}
		hbLAN = &cloud.HBLAN{
			Enabled: true,
			Uplink:  a.lanMgr.Uplink(),
			Routes:  routes,
		}
	}

	// ── System (extended stats) ───────────────────────────────────────────
	// Run with a tight 1s timeout so a slow /proc read never blocks the
	// heartbeat itself. On error / cancellation we leave System=nil — the
	// cloud can fall back to the legacy Metrics block.
	var hbSystem *cloud.HBSystem
	if a.sysstats != nil {
		sysCtx, sysCancel := context.WithTimeout(ctx, time.Second)
		snap, err := a.sysstats.Snapshot(sysCtx)
		sysCancel()
		if err != nil {
			log.Debug().Err(err).Msg("heartbeat: system snapshot failed — omitting System block")
		} else if snap != nil {
			hbSystem = &cloud.HBSystem{
				LoadAvg1:    snap.LoadAvg1,
				LoadAvg5:    snap.LoadAvg5,
				LoadAvg15:   snap.LoadAvg15,
				CPUUsage:    snap.CPUUsage,
				MemUsedPct:  snap.MemUsedPct,
				DiskUsedPct: snap.DiskUsedPct,
				TempCPU:     snap.TempCPU,
				Uptime:      snap.Uptime,
				CapturedAt:  snap.CapturedAt,
			}
			// Mirrors the library's own guard — below 5 samples the
			// percentile values are zeroed and would be misleading.
			if p := a.sysstats.Percentiles(); p.WindowSize >= 5 {
				hbSystem.Percentiles = &cloud.HBSystemPercentiles{
					P50Cpu:        p.P50Cpu,
					P95Cpu:        p.P95Cpu,
					P50Load:       p.P50Load,
					P95Load:       p.P95Load,
					WindowSize:    p.WindowSize,
					WindowMinutes: p.WindowMinutes,
				}
			}
		}
	}

	payload := cloud.HeartbeatPayload{
		RegistrationCode: a.identity.RegistrationCode,
		RegistrationPin:  a.identity.RegistrationPin,
		SerialNumber:     a.identity.SerialNumber,
		FirmwareVersion:  Version,
		Info:             info,
		Metrics:          hbMetrics,
		Network:          hbNetwork,
		VPN:              hbVPN,
		USB:              hbUSB,
		LAN:              hbLAN,
		System:           hbSystem,
	}

	resp, err := a.cloud.Heartbeat(ctx, payload)
	if err != nil {
		log.Warn().Err(err).Msg("heartbeat send failed")
		return
	}

	// Two response variants: "unclaimed" (no Device yet — waiting for the
	// user to claim on the dashboard) or "claimed" (normal operation). On
	// first transition to "claimed" we persist the DeviceID so rud1-app's
	// identity card can show the "paired" state.
	if resp.Status == "unclaimed" {
		log.Info().
			Str("registration_code", resp.RegistrationCode).
			Msg("heartbeat: device unclaimed — waiting for dashboard claim")
		return
	}
	if resp.DeviceID != "" && resp.DeviceID != a.identity.DeviceID {
		a.identity.DeviceID = resp.DeviceID
		a.identity.RegisteredAt = time.Now()
		if err := a.store.Save(a.identity); err != nil {
			log.Warn().Err(err).Msg("heartbeat: failed to persist device id")
		}
		log.Info().Str("device_id", resp.DeviceID).Msg("heartbeat: device claimed")
	}
	log.Debug().Msg("heartbeat sent")

	// In the no-hub world the VpnPeer block echoes the agent's own server
	// spec (subnet, pubkey). The agent has already applied it in New() —
	// but if the cloud reports a different subnet (e.g. because a previous
	// deployment used a different derivation) we re-apply.
	if resp.VpnPeer != nil {
		a.maybeReapplyServer(resp.VpnPeer)
	}

	// ClientPeers is the authoritative set of user peers for this device.
	// A nil slice means "no opinion" (legacy/unclaimed response); an empty
	// slice means "drop all peers". The apply call is best-effort — a
	// failure to wg-set one peer doesn't abort the others.
	if resp.ClientPeers != nil {
		a.applyClientPeers(resp.ClientPeers)
	}
}

// applyClientPeers converges the live WireGuard server state toward the
// authoritative `desired` set the cloud just echoed back. For every desired
// peer that is missing from `wg show dump`, we AddPeer; for every live peer
// not present in `desired`, we RemovePeer.
//
// Errors are logged, not returned — the caller is a heartbeat goroutine, and
// a single bad peer must not prevent the rest of the set from converging.
// On simulated hardware this is effectively a trace-only no-op (the
// underlying wireguard package skips the wg binary).
func (a *Agent) applyClientPeers(desired []cloud.ClientPeer) {
	iface := a.cfg.VPN.Interface
	live, err := wireguard.ListPeers(iface)
	if err != nil {
		log.Warn().Err(err).Msg("vpn: list peers failed — skipping peer sync")
		return
	}

	// Build a pubkey-indexed view of both sides so the diff is O(n+m).
	desiredByKey := make(map[string]cloud.ClientPeer, len(desired))
	for _, p := range desired {
		if p.PublicKey == "" {
			continue
		}
		desiredByKey[p.PublicKey] = p
	}
	liveByKey := make(map[string]wireguard.RuntimePeer, len(live))
	for _, p := range live {
		liveByKey[p.PublicKey] = p
	}

	// Add/refresh peers that should exist. AddPeer is idempotent, so
	// re-issuing a wg set with the same allowed-ips is cheap — we only
	// skip it when nothing changed to keep the logs quiet.
	var added, removed, refreshed int
	for key, p := range desiredByKey {
		if cur, ok := liveByKey[key]; ok {
			if cur.AllowedIPs == p.AllowedIPs {
				continue
			}
			if err := wireguard.AddPeer(iface, key, p.AllowedIPs, p.PersistentKeepalive); err != nil {
				log.Warn().Err(err).Str("pubkey", key).Msg("vpn: refresh peer failed")
				continue
			}
			refreshed++
			continue
		}
		if err := wireguard.AddPeer(iface, key, p.AllowedIPs, p.PersistentKeepalive); err != nil {
			log.Warn().Err(err).Str("pubkey", key).Msg("vpn: add peer failed")
			continue
		}
		added++
	}

	// Revoke peers the cloud no longer lists.
	for key := range liveByKey {
		if _, ok := desiredByKey[key]; ok {
			continue
		}
		if err := wireguard.RemovePeer(iface, key); err != nil {
			log.Warn().Err(err).Str("pubkey", key).Msg("vpn: remove peer failed")
			continue
		}
		removed++
	}

	if added+removed+refreshed > 0 {
		log.Info().
			Int("added", added).
			Int("removed", removed).
			Int("refreshed", refreshed).
			Int("desired", len(desiredByKey)).
			Int("live", len(liveByKey)).
			Msg("vpn: client peer set converged")
	}
}

// maybeReapplyServer handles the unusual case where the cloud tells us the
// server spec (subnet, interface Address) should differ from what we have
// installed. This typically only fires after a manual admin correction on
// the rud1-es side — normal heartbeats just echo our current subnet back
// and the `if fp == lastAppliedSubnet` guard makes this a no-op.
func (a *Agent) maybeReapplyServer(p *cloud.VpnPeer) {
	if p.Address == "" || p.Address == a.lastAppliedSubnet {
		return
	}
	privkeyPath := a.cfg.VPN.PrivateKeyPath
	if privkeyPath == "" {
		privkeyPath = filepath.Join(platform.DataDir(), "wg-server.key")
	}
	if err := a.writeServerConfigIfNeeded(privkeyPath, p.Address); err != nil {
		log.Warn().Err(err).Msg("vpn: failed to re-apply server config from heartbeat")
		return
	}
	a.lastAppliedSubnet = p.Address
	log.Info().
		Str("address", p.Address).
		Msg("vpn: server subnet updated from cloud")
}

// policySweepInterval is how often the agent re-checks currently-exported
// bus IDs against the active USB policy. Short enough that a stale
// permission (e.g. rule removed while a remote client was still attached)
// is revoked within a minute of the remote client detaching.
const policySweepInterval = 30 * time.Second

// policySweepLoop periodically invokes the USBIPHandler's policy
// re-enforcement so phantom exports / rule-drifted shares get cleaned up
// even if no explicit policy update came in.
func (a *Agent) policySweepLoop(ctx context.Context) {
	if a.usbipH == nil {
		return
	}
	ticker := time.NewTicker(policySweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			revoked, errs := a.usbipH.ReenforcePolicy()
			if len(revoked) > 0 {
				log.Info().Strs("busIds", revoked).Msg("usbip: periodic sweep revoked exports")
			}
			for _, err := range errs {
				log.Warn().Err(err).Msg("usbip: periodic sweep error")
			}
		}
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
