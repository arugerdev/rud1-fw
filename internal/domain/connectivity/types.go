// Package connectivity models how the device reaches the internet: WiFi
// client, 4G/LTE cellular (Sierra Wireless MC7700 HAT) and a local fallback
// access-point mode used for initial configuration.
//
// The domain layer defines pure data structures and the Service interface.
// All OS-level interaction (nmcli, mmcli, wpa_supplicant, hostapd) lives in
// the infrastructure layer so the agent stays testable and platform-aware.
package connectivity

import (
	"context"
	"time"
)

// Mode is the currently active connectivity mode.
type Mode string

const (
	// ModeWiFi — WiFi client is the primary uplink.
	ModeWiFi Mode = "wifi"
	// ModeCellular — LTE modem is the primary uplink.
	ModeCellular Mode = "cellular"
	// ModeAP — device is exposing its own setup hotspot (no internet).
	ModeAP Mode = "ap"
	// ModeEthernet — wired uplink; not user-managed but reported for UI clarity.
	ModeEthernet Mode = "ethernet"
	// ModeOffline — no backend is currently delivering internet.
	ModeOffline Mode = "offline"
)

// Preferred is the user's policy for choosing between backends when several
// are available. Auto = prefer WiFi, fall back to cellular.
type Preferred string

const (
	PreferredAuto     Preferred = "auto"
	PreferredWiFi     Preferred = "wifi"
	PreferredCellular Preferred = "cellular"
)

// Security models the authentication type of a WiFi network.
type Security string

const (
	SecurityOpen    Security = "open"
	SecurityWEP     Security = "wep"
	SecurityWPA     Security = "wpa"
	SecurityWPA2    Security = "wpa2"
	SecurityWPA3    Security = "wpa3"
	SecurityEAP     Security = "eap"
	SecurityUnknown Security = "unknown"
)

// WiFiNetwork is a single BSS discovered during a scan.
type WiFiNetwork struct {
	SSID       string   `json:"ssid"`
	BSSID      string   `json:"bssid,omitempty"`
	Security   Security `json:"security"`
	SignalDBm  int      `json:"signal_dbm"`  // RSSI, typically -90..-30
	SignalPct  int      `json:"signal_pct"`  // 0..100, rough quality hint
	FrequencyM int      `json:"frequency_mhz"`
	Channel    int      `json:"channel,omitempty"`
	InUse      bool     `json:"in_use"`  // currently associated
	Saved      bool     `json:"saved"`   // credentials persisted locally
	Hidden     bool     `json:"hidden,omitempty"`
}

// SavedWiFi is a network whose credentials we've persisted. Passwords are
// NEVER returned from the API — only metadata.
type SavedWiFi struct {
	SSID         string    `json:"ssid"`
	Security     Security  `json:"security"`
	AutoConnect  bool      `json:"auto_connect"`
	LastUsed     time.Time `json:"last_used,omitempty"`
	Priority     int       `json:"priority"`
}

// WiFiStatus is the live state of the WiFi client radio.
type WiFiStatus struct {
	Enabled       bool   `json:"enabled"`
	ConnectedSSID string `json:"connected_ssid,omitempty"`
	IPv4          string `json:"ipv4,omitempty"`
	SignalPct     int    `json:"signal_pct,omitempty"`
	Frequency     int    `json:"frequency_mhz,omitempty"`
	Interface     string `json:"interface,omitempty"`
}

// ConnectRequest is the payload for connecting to a WiFi network.
type ConnectRequest struct {
	SSID     string `json:"ssid"`
	Password string `json:"password,omitempty"` // omit for open networks
	Hidden   bool   `json:"hidden,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

// ── Cellular ────────────────────────────────────────────────────────────────

// SIMState reflects the physical SIM card and its authentication state.
type SIMState string

const (
	SIMAbsent    SIMState = "absent"
	SIMLocked    SIMState = "sim-pin"    // PIN required
	SIMPUK       SIMState = "sim-puk"    // PIN blocked, PUK required
	SIMUnlocked  SIMState = "ready"
	SIMFailure   SIMState = "failure"
	SIMUnknown   SIMState = "unknown"
)

// CellularStatus is a snapshot of the LTE modem.
type CellularStatus struct {
	Present        bool     `json:"present"`              // modem detected at all
	Model          string   `json:"model,omitempty"`      // e.g. "Sierra Wireless MC7700"
	Manufacturer   string   `json:"manufacturer,omitempty"`
	Firmware       string   `json:"firmware,omitempty"`
	IMEI           string   `json:"imei,omitempty"`
	SIMState       SIMState `json:"sim_state"`
	IMSI           string   `json:"imsi,omitempty"`
	Operator       string   `json:"operator,omitempty"`
	OperatorCode   string   `json:"operator_code,omitempty"`
	NetworkType    string   `json:"network_type,omitempty"` // e.g. "lte", "hspa", "gsm"
	SignalPct      int      `json:"signal_pct"`             // 0..100
	SignalDBm      int      `json:"signal_dbm,omitempty"`
	Roaming        bool     `json:"roaming"`
	Connected      bool     `json:"connected"`              // actively passing traffic
	IPv4           string   `json:"ipv4,omitempty"`
	APN            string   `json:"apn,omitempty"`
	Interface      string   `json:"interface,omitempty"`

	// Traffic counters since modem came up. Carriers may reset these at
	// monthly boundaries — the alerting is *local*, not carrier-truthy.
	RxBytes        uint64   `json:"rx_bytes"`
	TxBytes        uint64   `json:"tx_bytes"`
	BillingCycleMB uint64   `json:"billing_cycle_mb,omitempty"` // soft data-cap alert threshold (0 = disabled)
	DataCapMB      uint64   `json:"data_cap_mb,omitempty"`      // hard cap; agent will warn near this
}

// CellularConfig is what the user (or installer) can mutate on the modem.
type CellularConfig struct {
	Enabled    bool   `json:"enabled"`
	APN        string `json:"apn,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	DataCapMB  uint64 `json:"data_cap_mb,omitempty"`
	// Optional preferred-plan hint shown in the UI. Carriers in Spain we
	// default-recommend are cheap M2M/IoT plans; the UI renders this.
	RecommendedPlan string `json:"recommended_plan,omitempty"`
}

// PINRequest unlocks a locked SIM.
type PINRequest struct {
	PIN string `json:"pin"`
}

// ── AP (setup mode) ─────────────────────────────────────────────────────────

// APStatus is the state of the local setup hotspot.
type APStatus struct {
	Active     bool   `json:"active"`
	SSID       string `json:"ssid,omitempty"`
	// Password is returned because this is specifically the local
	// provisioning credential — it is printed on the device sticker and
	// shown in the panel to help the admin recover it.
	Password   string `json:"password,omitempty"`
	Interface  string `json:"interface,omitempty"`
	IPv4       string `json:"ipv4,omitempty"`
	ClientsNum int    `json:"clients,omitempty"`
	AutoStart  bool   `json:"auto_start"` // auto-raised when no uplink
}

// ── Aggregate state ─────────────────────────────────────────────────────────

// Snapshot is the whole connectivity picture exposed to the web panel in a
// single round-trip.
type Snapshot struct {
	Mode      Mode            `json:"mode"`
	Preferred Preferred       `json:"preferred"`
	Internet  bool            `json:"internet"`
	WiFi      *WiFiStatus     `json:"wifi,omitempty"`
	Cellular  *CellularStatus `json:"cellular,omitempty"`
	AP        *APStatus       `json:"ap,omitempty"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// ── Service ─────────────────────────────────────────────────────────────────

// Service is the orchestrator exposed to the HTTP layer.
type Service interface {
	// Snapshot returns a fresh picture of all connectivity backends.
	Snapshot(ctx context.Context) (*Snapshot, error)

	// Preferred lets the user pin a backend as primary (or Auto).
	SetPreferred(ctx context.Context, p Preferred) error

	// WiFi
	WiFiScan(ctx context.Context) ([]WiFiNetwork, error)
	WiFiSaved(ctx context.Context) ([]SavedWiFi, error)
	WiFiConnect(ctx context.Context, req ConnectRequest) error
	WiFiDisconnect(ctx context.Context) error
	WiFiForget(ctx context.Context, ssid string) error
	WiFiStatus(ctx context.Context) (*WiFiStatus, error)

	// Cellular
	CellularStatus(ctx context.Context) (*CellularStatus, error)
	CellularSetConfig(ctx context.Context, cfg CellularConfig) error
	CellularUnlockPIN(ctx context.Context, pin string) error
	CellularConnect(ctx context.Context) error
	CellularDisconnect(ctx context.Context) error

	// Access-point (setup mode)
	APStatus(ctx context.Context) (*APStatus, error)
	APEnable(ctx context.Context) error
	APDisable(ctx context.Context) error
	// APSetCredentials swaps the SSID and/or PSK the setup hotspot uses.
	// An empty ssid means "keep the current one"; password is mandatory
	// (≥ 8 chars, WPA2 floor). When the AP is currently active it is
	// reapplied with the new credentials in-place.
	APSetCredentials(ctx context.Context, ssid, password string) error
}
