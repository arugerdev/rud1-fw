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
type HBLAN struct {
	Enabled bool         `json:"enabled"`
	Uplink  string       `json:"uplink,omitempty"`
	Routes  []HBLANRoute `json:"routes,omitempty"`
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
