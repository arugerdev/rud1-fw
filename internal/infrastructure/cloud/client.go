// Package cloud implements an HTTP client for the rud1-es API.
package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is an HTTP client for the rud1-es cloud API.
type Client struct {
	baseURL    string
	apiSecret  string
	httpClient *http.Client
}

// New creates a Client targeting baseURL, authenticating with apiSecret.
func New(baseURL, apiSecret string, timeout time.Duration) *Client {
	return &Client{
		baseURL:  baseURL,
		apiSecret: apiSecret,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// ── Registration ─────────────────────────────────────────────────────────────

// RegisterRequest is the body sent to POST /api/v1/devices/register.
type RegisterRequest struct {
	RegistrationCode string `json:"registrationCode"`
	SerialNumber     string `json:"serialNumber,omitempty"`
	FirmwareVersion  string `json:"firmwareVersion,omitempty"`
	Platform         string `json:"platform,omitempty"`
	Arch             string `json:"arch,omitempty"`
}

// RegisterResponse is the body returned by a successful registration.
type RegisterResponse struct {
	OK             bool   `json:"ok"`
	DeviceID       string `json:"deviceId"`
	SerialNumber   string `json:"serialNumber"`
	OrganizationID string `json:"organizationId"`
}

// Register posts device registration data and returns the assigned identity.
// No auth header required — the registration code is the credential.
func (c *Client) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	resp, err := c.doJSON(ctx, http.MethodPost, "/api/v1/devices/register", "", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusConflict {
		return nil, fmt.Errorf("register: device already provisioned")
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("register: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var out RegisterResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("register: decode response: %w", err)
	}
	return &out, nil
}

// ── Heartbeat ────────────────────────────────────────────────────────────────

// HeartbeatPayload matches the nested schema expected by POST /api/v1/devices/heartbeat.
type HeartbeatPayload struct {
	RegistrationCode string     `json:"registrationCode"`
	// RegistrationPin is the 6-digit PIN from /boot/rud1-identity.json.
	// Required on the bootstrap heartbeat (no Device yet) so the cloud can
	// stage the DeviceIdentity row the user will claim against. Also
	// verified on every subsequent heartbeat to prevent a code-only attacker
	// from impersonating the device.
	RegistrationPin string     `json:"registrationPin,omitempty"`
	SerialNumber    string     `json:"serialNumber,omitempty"`
	FirmwareVersion string     `json:"firmwareVersion,omitempty"`
	Info            *HBInfo    `json:"info,omitempty"`
	Metrics         *HBMetrics `json:"metrics,omitempty"`
	Network         *HBNetwork `json:"network,omitempty"`
	VPN             *HBVPN     `json:"vpn,omitempty"`
	USB             *HBUSB     `json:"usb,omitempty"`
	LAN             *HBLAN     `json:"lan,omitempty"`
	// System is the extended host-stats subset populated from
	// sysstat.Collector. It overlaps Metrics intentionally — Metrics is the
	// legacy payload still consumed by older rud1-es code paths, while
	// System carries the richer figures (load averages, swap, etc.) the
	// dashboard health page needs. Nil when the snapshot failed or timed
	// out so the heartbeat stays send-first, metrics-second.
	System *HBSystem `json:"system,omitempty"`
	// Setup is the operator-supplied identification entered during the
	// first-boot wizard. Reported on every heartbeat once the Setup block
	// has been touched at least once so the cloud can render a nameplate
	// banner on the device detail page even if the user hasn't renamed
	// the cloud row yet. `Complete=false` means the device is still in
	// first-boot mode (AP raised, /api/setup/* open) — the cloud surfaces
	// that as a dedicated banner with a "Configure now" CTA.
	Setup *HBSetup `json:"setup,omitempty"`
	// TimeHealth is a compact snapshot of TZ + NTP state, populated only
	// when the agent's throttle says it's worth shipping (rising/falling
	// edge of any warning, NTP sync flip, TZ source flip — or once an
	// hour as a keepalive). Otherwise omitted to keep heartbeats small.
	// The cloud uses it to render a dedicated banner on the device
	// detail page; the operator-facing /api/system/time-health endpoint
	// remains the source of truth for the richer fields (Now, Timesyncd,
	// UTCOffset, Simulated).
	TimeHealth *HBTimeHealth `json:"timeHealth,omitempty"`
	// Audit is a rolling snapshot of the most recent config-mutation
	// audit entries (iter 30 disk-backed JSONL log). The agent forwards
	// up to MaxHBAuditEntries newest-first per heartbeat and the cloud
	// dedups by (deviceId, at, action, actor) so retransmissions are
	// idempotent. Omitted entirely when the audit log is unavailable
	// (LoggerNoop fallback) or when the most recent entries already
	// match the cursor the cloud last persisted (tracked locally in
	// `lastForwardedAuditAt`). Operators see the trail under
	// /dashboard/devices/[id]/audit without having to SSH into the Pi.
	Audit *HBAudit `json:"audit,omitempty"`
	// Config is a compact snapshot of operator-tunable system config
	// values the cloud needs to reflect on the dashboard or warn about
	// when they drift from an org-wide default. Currently carries the
	// effective audit-log retention window so /dashboard/devices/[id]/audit
	// can flag a divergence (e.g. operator dropped retention to 1 day on a
	// device under a 30-day compliance policy). Sent on every heartbeat —
	// tiny payload, no throttling, cloud overwrites on each tick.
	Config *HBConfigSnapshot `json:"config,omitempty"`
}

// HBTimeHealth is the compact subset of the time-health response that the
// cloud needs to render its banner. The HTTP-only fields (Now, Timesyncd,
// UTCOffsetSeconds, Simulated) are deliberately omitted: the cloud
// already knows the heartbeat's wall-clock arrival time, and the deeper
// systemd-timesyncd verdict is a debugging aid, not a banner input.
type HBTimeHealth struct {
	Timezone        string   `json:"timezone"`
	TimezoneSource  string   `json:"timezoneSource"`
	IsUTC           bool     `json:"isUTC"`
	NTPSynchronized bool     `json:"ntpSynchronized"`
	NTPEnabled      bool     `json:"ntpEnabled"`
	Warnings        []string `json:"warnings,omitempty"`
	CapturedAt      string   `json:"capturedAt"` // RFC3339, agent local clock
	// ClockSkewSeconds is the signed delta (NTP server − local) measured
	// at capture time, rounded to 3 decimals. Pointer-typed so the field
	// is omitted when the optional outbound probe is disabled or every
	// configured server failed — the cloud distinguishes "no probe data"
	// from "probe says drift is exactly zero". See iter 28 design notes.
	ClockSkewSeconds *float64 `json:"clockSkewSeconds,omitempty"`
}

// MaxHBAuditEntries caps the number of audit entries the agent forwards
// per heartbeat. The audit log is intentionally low-traffic (operator
// edits to TZ / NTP / setup happen a handful of times per day at most),
// so a 16-entry rolling window comfortably covers a typical incident
// response without ballooning heartbeat size. The cloud dedups by
// (deviceId, at, action, actor) so retransmissions are idempotent.
const MaxHBAuditEntries = 16

// HBAuditEntry is one config-mutation audit row forwarded over the
// heartbeat. Field-for-field mirror of `configlog.Entry` (sans the
// internal Error→Error truncation logic) so the cloud schema can stay
// stable even if the firmware extends the on-disk format. Previous and
// Next are arbitrary JSON values per the configlog contract.
type HBAuditEntry struct {
	At         int64  `json:"at"`
	Action     string `json:"action"`
	Actor      string `json:"actor,omitempty"`
	ResourceID string `json:"resourceId,omitempty"`
	Previous   any    `json:"previous,omitempty"`
	Next       any    `json:"next,omitempty"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
}

// HBAudit wraps the rolling audit-entry batch the agent ships per
// heartbeat. `Entries` is newest-first and capped at MaxHBAuditEntries.
// `LastAt` echoes the largest `at` in the batch so the cloud can compute
// "newest forwarded" without scanning the slice — useful for the audit
// page's freshness chip.
type HBAudit struct {
	Entries []HBAuditEntry `json:"entries"`
	LastAt  int64          `json:"lastAt,omitempty"`
}

// HBConfigSnapshot is the compact operator-tunable config snapshot
// forwarded with every heartbeat. Kept deliberately tiny: only the
// values the cloud needs to surface or alert on. New fields here must
// be `omitempty` and pointer-typed when "absent" needs to be
// distinguishable from "zero" — otherwise older firmware looks like a
// device that explicitly set the value to zero.
type HBConfigSnapshot struct {
	// AuditRetentionDays is the effective (post-clamp, [1, 365])
	// retention window in days for the on-disk JSONL audit log. Mirrors
	// `cfg.System.AuditRetentionDaysOrDefault()`. The cloud uses it to
	// flag drift against an org default on the per-device audit page.
	AuditRetentionDays int `json:"auditRetentionDays,omitempty"`
	// AuditRetentionStats (iter 35) is the disk-side inventory mirrored
	// from `GET /api/system/audit/retention`. Omitted (`nil`) when the
	// audit logger is unavailable (no /var/lib/rud1/audit, dev hardware)
	// so older cloud schemas still round-trip cleanly. Cloud renders an
	// "actual coverage" chip from these fields — useful when a Pi has
	// been offline and the on-disk window is shorter than the configured
	// retention.
	AuditRetentionStats *HBAuditRetentionStats `json:"auditRetentionStats,omitempty"`
	// LastDesiredConfigAppliedAt (iter 49) is the wall-clock time of the
	// most recent successful `desiredConfigApplier.Apply` that mutated
	// disk state. Lets the cloud confirm convergence directly instead of
	// inferring it from drift between the desired patch and the next
	// heartbeat snapshot. Nil/omitted when no cloud apply has ever
	// happened on this device (fresh boot, or only local PUTs so far).
	// RFC3339 UTC over the wire so the cloud parses with the same
	// constructor used by the audit-stats timestamps above.
	LastDesiredConfigAppliedAt *time.Time `json:"lastDesiredConfigAppliedAt,omitempty"`
	// LastDesiredConfigAppliedFields (iter 52) is the canonical
	// wire-name list of fields that mutated in the same Apply that
	// stamped LastDesiredConfigAppliedAt. Names match the JSON tags on
	// `DesiredConfigPatch` (e.g. ["auditRetentionDays","externalNTPServers"]).
	// Lets the cloud render a "last cloud push converged at HH:MM:SS
	// (fields: …)" chip on the device-detail page WITHOUT replaying the
	// desired-config emission queue to figure out which row converged.
	// Omitted when nil — older cloud schemas still parse cleanly because
	// the field is absent on iter ≤51 firmware.
	LastDesiredConfigAppliedFields []string `json:"lastDesiredConfigAppliedFields,omitempty"`
}

// HBAuditRetentionStats mirrors `audit/configlog.Stats` over the wire.
// Time fields use RFC3339 (UTC) so the cloud can parse them with the
// same Date constructor used elsewhere; nil means "unknown" — distinct
// from "epoch zero" which would be a misconfiguration.
//
// EntryBytes (iter 42) is the uncompressed JSONL footprint, paired with
// TotalBytes (the on-disk gzip-compressed footprint introduced in
// iter 41). The ratio is the operator-visible "is gzip working" signal
// on the audit retention chip. Marshalled `omitempty` so iter ≤41 fw
// (no awareness of the field) and iter ≤41 cloud (no consumer) keep
// round-tripping cleanly: zero on the wire means "unknown" — distinct
// from a real all-zero log which would also legitimately omit it.
//
// CompressionByDay (iter 44) is the per-day {dayKey -> ratio} histogram
// paired with the EntryBytes/TotalBytes aggregates. The cloud uses it
// to render outliers (e.g. one huge low-entropy day skewing the
// fleet-wide average from `computeFleetCompressionRatio`). Marshalled
// `omitempty` so iter ≤43 cloud schemas keep round-tripping; an empty
// map is also dropped because a brand-new device with no rotated
// archives yet has no useful per-day signal to surface.
type HBAuditRetentionStats struct {
	TotalEntries     int                `json:"totalEntries"`
	TotalBytes       int64              `json:"totalBytes"`
	EntryBytes       int64              `json:"entryBytes,omitempty"`
	FileCount        int                `json:"fileCount"`
	OldestEntryAt    string             `json:"oldestEntryAt,omitempty"`    // RFC3339 UTC; "" when unknown
	NewestEntryAt    string             `json:"newestEntryAt,omitempty"`    // RFC3339 UTC; "" when unknown
	LastPruneAt      string             `json:"lastPruneAt,omitempty"`      // RFC3339 UTC; "" when unknown
	CompressionByDay map[string]float64 `json:"auditCompressionByDay,omitempty"`
}

// HBSetup mirrors `cfg.Setup` over the heartbeat. Only sent when at least
// one of the operator-supplied fields is populated OR when Complete=false
// so the cloud always knows when a device is in first-boot mode.
type HBSetup struct {
	Complete       bool   `json:"complete"`
	DeviceName     string `json:"deviceName,omitempty"`
	DeviceLocation string `json:"deviceLocation,omitempty"`
	Notes          string `json:"notes,omitempty"`
	CompletedAt    int64  `json:"completedAt,omitempty"`
}

// HBSystem is the subset of sysstat.Stats propagated via heartbeats.
//
// It is deliberately narrower than the /api/system/stats response: the
// cloud only needs enough to plot health graphs and trigger alerts.
// Fields stay ordered to match the HTTP response for easy diffing.
type HBSystem struct {
	LoadAvg1    float64              `json:"loadAvg1"`
	LoadAvg5    float64              `json:"loadAvg5"`
	LoadAvg15   float64              `json:"loadAvg15"`
	CPUUsage    float64              `json:"cpuUsage"`
	MemUsedPct  float64              `json:"memUsedPct"`
	DiskUsedPct float64              `json:"diskUsedPct"`
	TempCPU     *float64             `json:"tempCpu,omitempty"`
	Uptime      int64                `json:"uptime"`
	CapturedAt  string               `json:"capturedAt,omitempty"`
	Percentiles *HBSystemPercentiles `json:"percentiles,omitempty"`
}

// HBSystemPercentiles mirrors sysstat.PercentilesSnapshot for transport
// inside the heartbeat. Populated only once the sampler has accumulated
// enough data for stable p50/p95 figures.
type HBSystemPercentiles struct {
	P50Cpu        float64 `json:"p50Cpu"`
	P95Cpu        float64 `json:"p95Cpu"`
	P50Load       float64 `json:"p50Load"`
	P95Load       float64 `json:"p95Load"`
	WindowSize    int     `json:"windowSize"`
	WindowMinutes int     `json:"windowMinutes"`
}

// HBLANRoute is a single LAN-exposure rule echoed in the heartbeat.
type HBLANRoute struct {
	Subnet  string `json:"subnet"`
	Applied bool   `json:"applied"`
}

// HBLAN tells the cloud which LAN subnets the Pi is actively NAT'ing for
// WG peers, so the cloud can advertise them in each client peer's
// AllowedIPs. `Enabled=false` or empty `Routes` ⇒ cloud ignores the field
// and emits only the Pi's own /24.
//
// LastAppliedAt is the wall-clock time of the most recent Apply() call on
// the lan.Manager (RFC3339, omitted when zero). Surfaced so the cloud
// dashboard can mirror the rud1-app StatusStrip's "Última sync" indicator
// — operators can confirm at a glance the kernel state matches what the
// cloud thinks without SSH'ing in.
type HBLAN struct {
	Enabled       bool         `json:"enabled"`
	Uplink        string       `json:"uplink,omitempty"`
	Routes        []HBLANRoute `json:"routes,omitempty"`
	LastAppliedAt string       `json:"lastAppliedAt,omitempty"`
	// Iter 58: digest of the first per-rule error from the most recent
	// Apply (empty when last apply was clean). Lets the cloud surface
	// "your LAN routing wedged on this rule" without making the operator
	// SSH in to read journalctl. Cleared on every successful Apply, so a
	// transient failure that recovers next iteration disappears from
	// the dashboard automatically.
	LastApplyError string `json:"lastApplyError,omitempty"`
}

// HBInfo carries static device identification fields.
type HBInfo struct {
	Hostname      string `json:"hostname"`
	AgentVersion  string `json:"agentVersion"`
	Platform      string `json:"platform"`
	Arch          string `json:"arch"`
	Simulated     bool   `json:"simulated"`
	KernelVersion string `json:"kernelVersion,omitempty"`
	OS            string `json:"os,omitempty"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
}

// HBMetrics carries live resource usage.
type HBMetrics struct {
	CPUUsage    float64  `json:"cpuUsage"`
	MemoryUsage float64  `json:"memoryUsage"`
	Temperature *float64 `json:"temperature,omitempty"`
	DiskUsage   *float64 `json:"diskUsage,omitempty"`
	Uptime      int64    `json:"uptime"`
	RxBytes     *int64   `json:"rxBytes,omitempty"`
	TxBytes     *int64   `json:"txBytes,omitempty"`
}

// HBNetworkInterface is one network interface in a heartbeat.
type HBNetworkInterface struct {
	Name       string   `json:"name"`
	MAC        string   `json:"mac"`
	MTU        int      `json:"mtu"`
	Up         bool     `json:"up"`
	IPv4       []string `json:"ipv4"`
	IPv6       []string `json:"ipv6"`
	IsLoopback bool     `json:"isLoopback"`
	IsWireless bool     `json:"isWireless"`
}

// HBNetwork carries a full network status snapshot.
type HBNetwork struct {
	Hostname   string               `json:"hostname"`
	Interfaces []HBNetworkInterface `json:"interfaces"`
	Gateway    string               `json:"gateway,omitempty"`
	DNS        []string             `json:"dns"`
	Internet   bool                 `json:"internet"`
}

// HBVPN carries WireGuard connection state.
// Only included when the VPN config exists and has a public key.
type HBVPN struct {
	InterfaceName string  `json:"interfaceName"`
	PublicKey     string  `json:"publicKey"` // device's own WG SERVER pubkey
	Address       string  `json:"address,omitempty"`
	Connected     bool    `json:"connected"`
	// Endpoint kept for legacy readers — equivalent to PublicEndpoint now.
	Endpoint        string  `json:"endpoint,omitempty"`
	// PublicEndpoint is the router-visible "host:port" the agent discovered
	// via UPnP / STUN / /echo-ip. rud1-es stores it on VpnConfig.endpoint
	// and serves it as the Endpoint in client .conf files.
	PublicEndpoint  string  `json:"publicEndpoint,omitempty"`
	// UPnPOK signals whether the NAT mapping was successfully negotiated.
	// Nil means we never tried; false means we tried and failed (fell back
	// to STUN + keepalive); true means the port is authoritatively open.
	UPnPOK          *bool   `json:"upnpOk,omitempty"`
	// NATType is the STUN-derived classification of our outgoing NAT:
	// "open" | "restricted" | "symmetric" | "unknown".
	NATType         string  `json:"natType,omitempty"`
	// CGNAT is true when the discovered public endpoint is inside RFC 6598
	// (100.64.0.0/10). The cloud surfaces this on the device card so the
	// operator gets an actionable warning before clicking Connect.
	CGNAT           bool    `json:"cgnat,omitempty"`
	AllowedIps      string  `json:"allowedIps,omitempty"`
	DNS             string  `json:"dns,omitempty"`
	PeerCount       int     `json:"peerCount"`
	// ActivePeers counts peers whose most recent handshake is within
	// 3 minutes (the WireGuard "fresh" window). Cheaper proxy for
	// "how many users are really connected right now" than PeerCount,
	// which reports every peer the cloud ever pushed.
	ActivePeers     int     `json:"activePeers"`
	LastHandshake   *string `json:"lastHandshake,omitempty"`
	// PeerTelemetry is the per-peer snapshot the Pi emits each heartbeat
	// so rud1-es can persist handshake freshness + cumulative bytes on
	// `UserVPNPeer` without having to reach into the Pi on demand.
	// Omitted when the VPN interface isn't up or listing failed.
	PeerTelemetry []HBVPNPeerTelemetry `json:"peerTelemetry,omitempty"`
	// Relay describes the state of the OUTBOUND wg-relay tunnel — non-nil
	// only when the cloud has previously assigned this device a relay peer
	// and the agent has materialised wg-relay locally. Tunnel up + recent
	// handshake means relay-mode users can reach the Pi via the VPS; a
	// stale handshake while relay mode is supposed to be active surfaces
	// "VPS unreachable from Pi" on the cloud side.
	Relay *HBVPNRelay `json:"relay,omitempty"`
}

// HBVPNRelay carries the agent's view of its wg-relay outbound tunnel.
// Reported only when the cloud's last heartbeat response delivered a
// relayPeer block — when the cloud demotes the device back to direct
// (relayPeer:null), the agent tears wg-relay down and stops emitting
// this block. The cloud uses LastHandshake to detect "Pi can't reach
// VPS" without polling the relay independently.
type HBVPNRelay struct {
	InterfaceName string  `json:"interfaceName"`
	// TunnelUp signals that wg-quick has the iface up AND the kernel
	// reports a peer (the VPS). False covers both "interface absent"
	// and "peer never installed" — distinguishable from log lines but
	// indistinct on the wire because rud1-es only cares about the
	// binary "is the relay path viable right now" answer.
	TunnelUp      bool    `json:"tunnelUp"`
	// Address is the Pi's relay /32, e.g. "10.99.42.1/32" — echoed
	// back so the cloud can spot drift between what it assigned and
	// what the agent actually applied.
	Address       string  `json:"address,omitempty"`
	// LastHandshake is the most recent successful handshake on the
	// outbound tunnel, RFC3339 UTC. Empty when the tunnel just came
	// up and hasn't completed its first handshake yet.
	LastHandshake string  `json:"lastHandshake,omitempty"`
	// Endpoint is the VPS endpoint the kernel actually dialled —
	// useful for diagnosing DNS-resolution drift across heartbeats
	// (e.g. operator changed the DNS A record but the agent cached
	// the old IP via the kernel).
	Endpoint      string  `json:"endpoint,omitempty"`
	BytesRx       uint64  `json:"bytesRx"`
	BytesTx       uint64  `json:"bytesTx"`
}

// HBVPNPeerTelemetry is one `wg show dump` row serialised for the cloud.
// PublicKey is the peer's WG pubkey (matches `UserVPNPeer.publicKey` in
// rud1-es). LastHandshake is RFC3339 UTC; empty when never. Endpoint is
// the router-visible "host:port" seen by the Pi (useful for detecting
// asymmetric-NAT / split-horizon from the cloud side). BytesRx/Tx are
// cumulative since the wg interface came up on the Pi.
type HBVPNPeerTelemetry struct {
	PublicKey     string `json:"publicKey"`
	LastHandshake string `json:"lastHandshake,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
	BytesRx       uint64 `json:"bytesRx"`
	BytesTx       uint64 `json:"bytesTx"`
}

// HBUSBDevice is one USB device in a heartbeat.
type HBUSBDevice struct {
	BusID       string  `json:"busId"`
	VendorID    string  `json:"vendorId"`
	ProductID   string  `json:"productId"`
	VendorName  *string `json:"vendorName,omitempty"`
	ProductName *string `json:"productName,omitempty"`
	Serial      *string `json:"serial,omitempty"`
	Shared      bool    `json:"shared"`
}

// HBUSB wraps the USB device list and USB/IP server state.
type HBUSB struct {
	Devices        []HBUSBDevice `json:"devices"`
	UsbipEnabled   bool          `json:"usbipEnabled"`
	ExportedBusIDs []string      `json:"exportedBusIds,omitempty"`
	// InUseBusIDs lists bus IDs for which the kernel reports an active
	// remote client attachment (usbip_status == 3). Useful for the
	// Connect tab's "Attached" badge and for the VPN_DOWN cleanup logic.
	InUseBusIDs []string `json:"inUseBusIds,omitempty"`
}

// VpnPeer is the [Peer] block the cloud pushes to the agent when it has
// assigned this device a tunnel address. The agent materialises a full
// wg0.conf from it. All fields are required when VpnPeer is non-nil.
type VpnPeer struct {
	ServerPublicKey     string  `json:"serverPublicKey"`
	Endpoint            string  `json:"endpoint"`
	Address             string  `json:"address"`    // e.g. "10.200.1.7/32"
	AllowedIPs          string  `json:"allowedIps"` // e.g. "10.200.0.0/16"
	DNS                 *string `json:"dns"`
	PersistentKeepalive int     `json:"persistentKeepalive"`
}

// RelayPeer is the cloud→agent assignment for the OUTBOUND wg-relay
// tunnel. Non-nil tells the agent to bring up `wg-relay` against the
// VPS at `Endpoint`, with the Pi's assigned `Address` and a wide
// AllowedIPs catching the relay subnet so users can reach the Pi
// through it. Strict omitempty on the wire — older firmware predating
// relay support ignores unknown fields, so emitting nothing keeps
// them quiet.
//
// The agent treats this block as the SOURCE OF TRUTH for the relay
// tunnel: it will tear `wg-relay` down on every heartbeat that omits
// the field. Operators flipping a device from FORCE_RELAY back to
// AUTO/DIRECT_ONLY thus reach steady state on the next heartbeat tick
// without needing a config push or device reboot.
type RelayPeer struct {
	ServerPublicKey     string `json:"serverPublicKey"`
	Endpoint            string `json:"endpoint"`            // e.g. "vps.rud1.es:51820"
	Address             string `json:"address"`             // e.g. "10.99.42.1/32"
	AllowedIPs          string `json:"allowedIps"`          // e.g. "10.99.0.0/16"
	PersistentKeepalive int    `json:"persistentKeepalive"` // typically 25
}

// ClientPeer is one [Peer] block installed on the Pi's WG server for a
// specific end user. The cloud returns the authoritative set in every
// heartbeat — the agent diffs against `wg show dump` and calls
// `wireguard.AddPeer` / `wireguard.RemovePeer` to converge.
//
// AllowedIPs is typically a single /32 (e.g. "10.77.42.17/32") — the
// user's assigned peer IP inside this device's subnet. PersistentKeepalive
// is advisory (applied only if > 0).
type ClientPeer struct {
	PublicKey           string `json:"publicKey"`
	AllowedIPs          string `json:"allowedIps"`
	PersistentKeepalive int    `json:"persistentKeepalive,omitempty"`
}

// HeartbeatResponse is the body returned by POST /api/v1/devices/heartbeat.
// Two variants: "unclaimed" (the cloud has no Device for this code yet — user
// hasn't claimed; agent should park with a waiting indicator) and "claimed".
type HeartbeatResponse struct {
	OK                 bool   `json:"ok"`
	// Status is "claimed" or "unclaimed". Older firmware pre-pivot doesn't
	// branch on this; new firmware MUST check before trusting DeviceID.
	Status             string `json:"status,omitempty"`
	// RegistrationCode echoes the code on unclaimed responses so the agent
	// can log it without inspecting its own config.
	RegistrationCode   string `json:"registrationCode,omitempty"`
	DeviceID           string `json:"deviceId,omitempty"`
	NextCheckInSeconds int    `json:"nextCheckInSeconds"`
	// VpnPeer (claimed only): the peer descriptor the device applies locally.
	// In the post-2026-04-22 no-hub world this describes the agent's OWN WG
	// server (subnet + own pubkey echo), not a remote hub.
	VpnPeer *VpnPeer `json:"vpnPeer,omitempty"`
	// ClientPeers (claimed only): the authoritative set of user peers the
	// cloud wants installed on this device's wg0 server. The agent diffs
	// against `wg show dump` and adds/removes to converge. A nil slice (or
	// missing field) means "no opinion — keep current peers" (legacy
	// response). An empty slice `[]` means "drop all client peers".
	ClientPeers []ClientPeer `json:"clientPeers,omitempty"`
	// AuditAckAt (iter 38): the cloud's explicit ack timestamp covering
	// only the audit entries it actually persisted. The agent caps its
	// local cursor advance to min(intendedCursor, *AuditAckAt) so a cloud
	// pipeline failure AFTER the HTTP-200 (e.g. db rollback, dedup error)
	// doesn't lose entries from the fw cursor's perspective. When nil the
	// agent falls back to the iter-37 behavior (advance to local intended
	// cursor — the max `at` of the batch we shipped this tick).
	AuditAckAt *time.Time `json:"auditAckAt,omitempty"`
	// DesiredConfig (iter 48) is the cloud→agent config-patch ingestion
	// channel. Until iter 48 the cloud client was outbound-only —
	// `HBConfigSnapshot` reported the agent's effective config but an
	// operator changing e.g. `auditRetentionDays` from rud1-es had no
	// transport to reach the device. The cloud now piggy-backs the
	// patch on the heartbeat response: when non-nil the agent validates
	// each field through the existing config helpers, persists via the
	// atomic `cfg.Save()` path, and re-arms whatever runtime trigger
	// the changed field is wired to (e.g. the iter-39 prune-on-shrink).
	// Fields are pointer-typed so absent vs. explicit-zero stay
	// distinguishable; unknown fields are silently ignored (forward-
	// compat — DisallowUnknownFields is intentionally NOT set).
	DesiredConfig *DesiredConfigPatch `json:"desiredConfig,omitempty"`
	// RelayPeer (claimed only): the cloud's assignment for the
	// agent-managed wg-relay outbound tunnel. Non-nil = bring it up
	// (or refresh the existing tunnel) against the rud1-vps relay at
	// `Endpoint`. Nil/absent = tear it down idempotently. The cloud
	// emits this whenever the device is in (or should be in) relay
	// mode AND a relay row is reachable; otherwise the field is
	// omitted so older firmware sees no change in the response shape.
	RelayPeer *RelayPeer `json:"relayPeer,omitempty"`
}

// DesiredConfigPatch carries the operator-tunable fields the cloud
// wants applied locally. Pointer-typed fields are required so the
// agent can distinguish "field omitted" from "explicit value 0". A
// nil patch (or every field nil) is a no-op — the agent does NOT
// rewrite config to disk in that case.
//
// Forward-compatibility: new fields land here as additional pointer
// members. The agent decoder uses stdlib defaults (no
// DisallowUnknownFields) so a cloud running ahead of the agent can
// add fields without breaking older firmware.
type DesiredConfigPatch struct {
	// AuditRetentionDays mirrors `cfg.System.AuditRetentionDays`. The
	// agent validates against `[MinAuditRetentionDays,
	// MaxAuditRetentionDays]` (same window the local PUT handler
	// enforces) before persisting. A change triggers an immediate
	// SetMaxFiles + PruneOld on the live disk logger when the new
	// value is strictly smaller than the previous effective window —
	// matching the iter-39 prune-on-shrink contract.
	AuditRetentionDays *int `json:"auditRetentionDays,omitempty"`

	// ExternalNTPProbeEnabled mirrors `cfg.System.ExternalNTPProbeEnabled`
	// (iter 50). A change re-arms the runtime time-health handler via
	// SetProbeOptions AND resets the heartbeat throttle so the next
	// tick re-emits the (potentially changed) timeHealth block instead
	// of waiting for the 1h keepalive — same observable behaviour as
	// `PUT /api/system/ntp-probe-config`.
	ExternalNTPProbeEnabled *bool `json:"externalNTPProbeEnabled,omitempty"`

	// ExternalNTPServers mirrors `cfg.System.ExternalNTPServers` (iter 50).
	// The agent normalises the list (trim, drop empties, dedupe
	// case-insensitively) and rejects when more than MaxNTPProbeServers
	// remain — same window the local PUT enforces. An explicit empty
	// slice clears the list (probe becomes effectively disabled regardless
	// of the Enabled flag — matches the local PUT semantics).
	ExternalNTPServers *[]string `json:"externalNTPServers,omitempty"`

	// LANRoutes mirrors `cfg.LAN.Routes` (iter 51). Each entry is a CIDR
	// the agent must validate via `lan.ValidateRoute(...)` against the
	// device's own WG /24 (no overlap, IPv4 only, mask < 32). The agent
	// normalises the list (trim, dedupe on canonical CIDR form, cap at
	// MaxDesiredLANRoutes) before persisting and re-applies the post-
	// normalize set through `lan.Manager.Apply(...)` — observationally
	// identical to the local `PUT /api/lan/routes` with `routes:[…]`.
	// An explicit empty slice clears the list AND tears down any live
	// iptables rules for previously-applied routes. The Enabled flag is
	// not exposed here on purpose: the cloud only owns the route list,
	// the operator still owns the global on/off via the local panel.
	LANRoutes *[]string `json:"lanRoutes,omitempty"`

	// ExternalNTPProbeTimeoutSeconds (iter 53) mirrors
	// `cfg.System.ExternalNTPProbeTimeout` as integer seconds — the cap
	// applied to each per-server SNTP attempt. The agent validates
	// against `[MinDesiredNTPProbeTimeoutSeconds,
	// MaxDesiredNTPProbeTimeoutSeconds]` (1..30s) before persisting.
	// A change re-arms the time-health handler via the iter-50
	// NTPApplyHook (the hook signature already takes per-server
	// timeout). Wire-shape is integer seconds (not a Go-style
	// duration string) so a non-Go cloud client doesn't need a
	// duration parser to write valid patches.
	ExternalNTPProbeTimeoutSeconds *int `json:"externalNTPProbeTimeoutSeconds,omitempty"`

	// CellularDataCapMB (iter 54) mirrors `cfg.Network.CellularDataCapMB`
	// — the soft cap (in megabytes) the local panel uses to warn the
	// operator before the cellular plan runs out. The agent validates
	// against `[MinDesiredCellularDataCapMB, MaxDesiredCellularDataCapMB]`
	// (0..1_000_000 MB, where 0 means "unlimited / no warning") before
	// persisting. No runtime re-arm is needed: the existing connectivity
	// supervisor reads the value on its next dial cycle. Wire-shape is
	// `*int` (not `*uint64`) so a JSON push of a stray negative number
	// surfaces as an explicit out-of-range error instead of silently
	// wrapping into a 64-bit billion-MB cap. Forward-compat: older
	// firmware (iter ≤53) ignores this field — the int→uint64 widening
	// happens inside the agent applier.
	CellularDataCapMB *int `json:"cellularDataCapMB,omitempty"`
}

// Heartbeat sends a device heartbeat authenticated with the shared API secret.
func (c *Client) Heartbeat(ctx context.Context, payload HeartbeatPayload) (*HeartbeatResponse, error) {
	resp, err := c.doJSON(ctx, http.MethodPost, "/api/v1/devices/heartbeat", c.apiSecret, payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("heartbeat: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var out HeartbeatResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("heartbeat: decode response: %w", err)
	}
	return &out, nil
}

// ── Firmware ─────────────────────────────────────────────────────────────────

// FirmwarePending describes an available firmware update returned by the cloud.
type FirmwarePending struct {
	RolloutID   string
	Version     string
	URL         string
	SHA256      string
}

type firmwarePendingResponse struct {
	Pending     bool   `json:"pending"`
	RolloutID   string `json:"rolloutId"`
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
	DownloadURL string `json:"downloadUrl"`
}

// CheckFirmware queries for a pending firmware update by registration code.
// Returns nil if no update is available.
func (c *Client) CheckFirmware(ctx context.Context, registrationCode string) (*FirmwarePending, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/api/v1/devices/firmware/pending", nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Set("registrationCode", registrationCode)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Authorization", "Bearer "+c.apiSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("check firmware: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("check firmware: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var out firmwarePendingResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("check firmware: decode response: %w", err)
	}
	if !out.Pending {
		return nil, nil
	}
	return &FirmwarePending{
		RolloutID: out.RolloutID,
		Version:   out.Version,
		URL:       out.DownloadURL,
		SHA256:    out.SHA256,
	}, nil
}

// AckFirmware reports the result of a firmware installation to the cloud.
// status should be "COMPLETED" or "FAILED".
func (c *Client) AckFirmware(ctx context.Context, rolloutID, registrationCode, status, errMsg string) error {
	body := map[string]any{
		"rolloutId":        rolloutID,
		"registrationCode": registrationCode,
		"status":           status,
	}
	if errMsg != "" {
		body["errorMsg"] = errMsg
	}

	resp, err := c.doJSON(ctx, http.MethodPost, "/api/v1/devices/firmware/ack", c.apiSecret, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ack firmware: unexpected status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

// doJSON marshals body and issues an HTTP request with JSON content-type.
// If token is non-empty it is sent as Bearer auth.
func (c *Client) doJSON(ctx context.Context, method, path, token string, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	return resp, nil
}
