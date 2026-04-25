// Package config loads the agent configuration from a YAML file, with
// sensible defaults and environment-variable overrides.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"

	"github.com/rud1-es/rud1-fw/internal/platform"
)

// Config is the top-level agent configuration.
type Config struct {
	LogLevel string        `yaml:"log_level"`
	Server   ServerConfig  `yaml:"server"`
	Cloud    CloudConfig   `yaml:"cloud"`
	VPN      VPNConfig     `yaml:"vpn"`
	USB      USBConfig     `yaml:"usb"`
	Network  NetworkConfig `yaml:"network"`
	LAN      LANConfig     `yaml:"lan"`
	Setup    SetupConfig   `yaml:"setup"`
	System   SystemConfig  `yaml:"system"`

	// Path is the filesystem location the config was loaded from. Set by
	// Load(); used by runtime Save() calls so the agent can persist mutations
	// (e.g. USB policy edits from the local panel) back to the same file.
	// Tagged `-` so it is never serialised into the YAML body.
	Path string `yaml:"-"`
}

// SystemConfig holds host-level diagnostics knobs. Today only the
// external-NTP probe lives here; future iterations may add other
// telemetry-only toggles without churning the top-level Config struct.
type SystemConfig struct {
	// ExternalNTPProbeEnabled flips on a one-shot SNTP query against
	// ExternalNTPServers each time /api/system/time-health is requested
	// (or the agent's heartbeat throttle decides to refresh the
	// timeHealth block). Default false — the existing timedatectl
	// signal is sufficient for most installs and the probe adds an
	// outbound UDP query the operator may not want.
	ExternalNTPProbeEnabled bool `yaml:"external_ntp_probe_enabled"`
	// ExternalNTPServers is the ordered server list the probe walks
	// through; the first to reply within ExternalNTPProbeTimeout wins.
	// Each entry is a "host" or "host:port" — `:123` is implied when
	// the port is omitted. Empty list disables the probe regardless of
	// the Enabled flag (defensive: a misconfigured YAML can't accidentally
	// flood the default pool with traffic).
	ExternalNTPServers []string `yaml:"external_ntp_servers,omitempty"`
	// ExternalNTPProbeTimeout caps each per-server attempt. 2s is the
	// default and matches the heartbeat's 1s budget headroom.
	ExternalNTPProbeTimeout time.Duration `yaml:"external_ntp_probe_timeout"`
	// AuditRetentionDays caps how many daily-rotated config-mutation
	// audit log files the agent keeps on disk. 0 (the default) maps to
	// 14 days — two weeks is enough for most operators to triage
	// recent changes. Deployments with stricter compliance windows can
	// crank this up; the value is clamped to [1, 365] in Validate so a
	// stray edit can't disable retention or balloon disk use. Operators
	// set it in config.yaml and restart the agent — there is no runtime
	// HTTP toggle by design.
	AuditRetentionDays int `yaml:"audit_retention_days"`
}

// AuditRetentionDaysOrDefault returns the effective retention window in
// days, applying the same default + clamp the validator would. It is
// intended for the agent boot path where a config-set-but-Validate-not-
// yet-called code path could otherwise smuggle a 0 into configlog.New
// (which would itself default to 14 — the goal here is to keep the
// fallback in one place so future tweaks land in both validation and
// runtime wiring).
func (s SystemConfig) AuditRetentionDaysOrDefault() int {
	d := s.AuditRetentionDays
	if d <= 0 {
		return DefaultAuditRetentionDays
	}
	if d > MaxAuditRetentionDays {
		return MaxAuditRetentionDays
	}
	return d
}

// DefaultAuditRetentionDays / MaxAuditRetentionDays parameterise the
// audit-log retention window. The default mirrors configlog's own
// historical default (two weeks); the max is one year — a soft ceiling
// that keeps disk use bounded for low-traffic devices that may run for
// years without operator attention.
const (
	DefaultAuditRetentionDays = 14
	MaxAuditRetentionDays     = 365
)

// NetworkConfig controls the WiFi / cellular / setup-AP subsystem.
//
// Defaults are tuned for a Raspberry Pi 3 with the stock onboard WiFi and an
// optional Sierra Wireless MC7700 cellular HAT. Users can override any field
// via /etc/rud1-agent/config.yaml.
type NetworkConfig struct {
	// WiFiInterface is the NIC the WiFi client uses (usually "wlan0").
	WiFiInterface string `yaml:"wifi_interface"`
	// APInterface is the NIC used for the setup hotspot. Typically the same
	// as WiFiInterface — NM will tear down the client to bring up the AP.
	APInterface string `yaml:"ap_interface"`
	// APSSID is the hotspot name. If left blank, defaults to
	// "Rud1-Setup-XXXX" with the last 4 hex chars of the machine-id so
	// multiple devices on the same installer's laptop are disambiguated.
	APSSID string `yaml:"ap_ssid"`
	// APPassword seeds the hotspot. If blank, the agent derives a stable
	// 10-char password from the machine-id and writes it to
	// /var/lib/rud1-agent/setup-ap.txt so the admin can retrieve it.
	APPassword string `yaml:"ap_password"`
	// APCIDR is the IPv4 range served on the hotspot, e.g. "192.168.50.1/24".
	APCIDR string `yaml:"ap_cidr"`
	// AutoAP: let the supervisor raise the hotspot automatically when the
	// device has been offline for longer than OfflineGrace.
	AutoAP bool `yaml:"auto_ap"`
	// OfflineGrace: how long (in seconds) to tolerate no internet before
	// raising the AP. Must be positive if AutoAP is true.
	OfflineGraceSeconds int `yaml:"offline_grace_seconds"`
	// CellularAPN: default APN attempted on first cellular connect.
	CellularAPN string `yaml:"cellular_apn"`
	// CellularDataCapMB: soft cap used by the UI to warn the user before
	// the plan runs out. 0 disables the warning.
	CellularDataCapMB uint64 `yaml:"cellular_data_cap_mb"`
	// PreferredUplink: auto | wifi | cellular
	PreferredUplink string `yaml:"preferred_uplink"`
}

// ServerConfig configures the local HTTP API consumed by rud1-app.
type ServerConfig struct {
	Host           string        `yaml:"host"`
	Port           int           `yaml:"port"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	AllowedOrigins []string      `yaml:"allowed_origins"`
	AuthToken      string        `yaml:"auth_token"` // optional bearer for the local API
}

// CloudConfig configures the connection to rud1-es (the Enterprise Server).
type CloudConfig struct {
	Enabled           bool          `yaml:"enabled"`
	BaseURL           string        `yaml:"base_url"`
	APISecret         string        `yaml:"api_secret"`
	RegistrationCode  string        `yaml:"registration_code"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	HTTPTimeout       time.Duration `yaml:"http_timeout"`
}

// VPNConfig configures the WireGuard adapter managed by the agent.
type VPNConfig struct {
	Interface  string `yaml:"interface"`
	ConfigPath string `yaml:"config_path"`
	// PubkeyPath is the world-readable mirror of the device's WG public key
	// (written by install.sh — see deploy/rpi/install.sh `WG_PUB_PUBLIC`).
	// The agent reads it on every heartbeat to advertise the device's pubkey
	// to the cloud, so the hub can allocate a peer for it on first contact.
	PubkeyPath string `yaml:"pubkey_path"`
	// PrivateKeyPath is the root-only file holding the device's WG private key
	// (generated by install.sh — see `WG_PRIV`). The agent reads it when the
	// cloud returns a `vpnPeer` block in the heartbeat response so it can
	// materialise a complete wg0.conf.
	PrivateKeyPath string `yaml:"private_key_path"`
}

// LANConfig configures the Pi's LAN-exposure behaviour over WireGuard.
//
// When Enabled is true and one or more Routes are declared, the agent:
//   1. Flips `net.ipv4.ip_forward=1` on the host.
//   2. Inserts an `iptables -t nat -A POSTROUTING -s <route> -o <uplink>
//      -j MASQUERADE` rule per route so packets from WG peers hitting a
//      LAN subnet get NAT'd out the uplink.
//   3. Advertises the routes in the heartbeat so rud1-es can broaden the
//      client peers' AllowedIPs to include them.
//
// Routes are CIDR strings (e.g. "192.168.1.0/24"). They must not overlap
// the WG subnet — the agent rejects overlapping entries at API level.
// UplinkInterface defaults to "eth0" on the Pi; if blank, the agent
// auto-detects the default-route interface at apply-time.
type LANConfig struct {
	Enabled         bool     `yaml:"enabled"`
	UplinkInterface string   `yaml:"uplink_interface,omitempty"`
	Routes          []string `yaml:"routes,omitempty"`
}

// SetupConfig captures the first-boot wizard state. It is intentionally
// short — the wizard collects only the bits that downstream code (cloud
// heartbeat, panel header, support tooling) needs to identify the device
// for an operator. The Complete flag gates two behaviours:
//
//  1. The supervisor keeps the setup-AP up indefinitely while !Complete so
//     a freshly imaged Pi is always reachable from an installer's phone.
//  2. /api/setup/{state,general,complete,health} skip BearerAuth while
//     !Complete (chicken-and-egg: the installer hasn't agreed a token yet).
//     Once Complete flips to true those endpoints lock down to require auth
//     so a paired device doesn't expose mutation surface to its LAN.
//
// All fields are filled by POST /api/setup/general from the wizard UI; the
// agent never writes them on its own.
type SetupConfig struct {
	Complete       bool   `yaml:"complete"`
	DeviceName     string `yaml:"device_name"`
	DeviceLocation string `yaml:"device_location"`
	Notes          string `yaml:"notes,omitempty"`
	CompletedAt    int64  `yaml:"completed_at,omitempty"` // unix seconds
}

// USBConfig configures the USB-over-IP subsystem.
type USBConfig struct {
	BindPort       int      `yaml:"bind_port"`
	USBIPEnabled   bool     `yaml:"usbip_enabled"`
	AuthorizedNets []string `yaml:"authorized_nets"` // CIDRs allowed to attach USB devices

	// Policy gates which physical USB devices can be shared over USB/IP.
	// An empty Policy.Allow list means "allow all devices" (back-compat);
	// when non-empty, attach requests are rejected unless the device matches.
	// Deny entries always win and are evaluated first.
	Policy USBPolicyConfig `yaml:"policy"`
}

// USBPolicyConfig is the attach-time allow/deny policy for USB/IP sharing.
//
// Each rule matches by VendorID:ProductID (4-digit hex, lowercase) and
// optionally a Serial (exact match). An empty Serial matches any serial.
// Rules are additive: a device matches if ANY Allow rule matches, and is
// rejected if ANY Deny rule matches.
type USBPolicyConfig struct {
	Allow []USBPolicyRule `yaml:"allow"`
	Deny  []USBPolicyRule `yaml:"deny"`
}

// USBPolicyRule is a single vendor/product (+ optional serial) match.
type USBPolicyRule struct {
	VendorID  string `yaml:"vendor_id"`
	ProductID string `yaml:"product_id"`
	Serial    string `yaml:"serial,omitempty"`
}

// Default returns a Config populated with reasonable defaults.
func Default() *Config {
	return &Config{
		LogLevel: "info",
		Server: ServerConfig{
			Host:           "127.0.0.1",
			Port:           7070,
			ReadTimeout:    15 * time.Second,
			WriteTimeout:   30 * time.Second,
			AllowedOrigins: []string{"http://localhost:5173", "http://localhost:3000"},
		},
		Cloud: CloudConfig{
			Enabled:           false,
			BaseURL:           "https://rud1.es",
			HeartbeatInterval: 60 * time.Second,
			HTTPTimeout:       20 * time.Second,
		},
		VPN: VPNConfig{
			Interface:      "wg0",
			ConfigPath:     filepath.Join(platform.ConfigDir(), "wg0.conf"),
			PubkeyPath:     filepath.Join(platform.ConfigDir(), "wg-pubkey.txt"),
			PrivateKeyPath: "/etc/wireguard/privatekey",
		},
		USB: USBConfig{
			BindPort: 3240,
		},
		Network: NetworkConfig{
			WiFiInterface: "wlan0",
			APInterface:   "wlan0",
			APCIDR:        "192.168.50.1/24",
			AutoAP:        true,
			// Aggressively short by design — installer UX trumps the
			// flap-prevention margin you'd want on a long-lived device.
			// Once the setup wizard has flipped Setup.Complete=true the
			// supervisor reverts to its boot-grace-then-threshold logic.
			OfflineGraceSeconds: 15,
			PreferredUplink:     "auto",
		},
		Setup: SetupConfig{
			Complete: false,
		},
		System: SystemConfig{
			ExternalNTPProbeEnabled: false,
			ExternalNTPServers:      nil,
			ExternalNTPProbeTimeout: 2 * time.Second,
			AuditRetentionDays:      DefaultAuditRetentionDays,
		},
	}
}

// Load reads a YAML file at path (or platform.ConfigDir()/config.yaml if
// path is empty), then applies environment-variable overrides. Any
// missing file falls back to sensible defaults rather than erroring.
func Load(path string) (*Config, error) {
	// Load .env file next to the binary if present (dev convenience).
	_ = godotenv.Load()

	cfg := Default()

	if path == "" {
		path = filepath.Join(platform.ConfigDir(), "config.yaml")
	}
	cfg.Path = path

	data, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		// Fall through; we will just use defaults + env.
	case err != nil:
		return nil, fmt.Errorf("read config: %w", err)
	default:
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	applyEnv(cfg)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate performs basic sanity checks.
func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port out of range: %d", c.Server.Port)
	}
	if c.Cloud.Enabled {
		if c.Cloud.BaseURL == "" {
			return fmt.Errorf("cloud.base_url is required when cloud is enabled")
		}
		if c.Cloud.APISecret == "" {
			return fmt.Errorf("cloud.api_secret is required when cloud is enabled")
		}
	}
	// Audit retention: clamp into [1, 365] with 0 / negative meaning
	// "use the default". We clamp rather than reject so a typo in
	// config.yaml never prevents the agent from booting — operator
	// surface (the audit log) is best-effort, not safety-critical.
	if c.System.AuditRetentionDays <= 0 {
		c.System.AuditRetentionDays = DefaultAuditRetentionDays
	} else if c.System.AuditRetentionDays > MaxAuditRetentionDays {
		c.System.AuditRetentionDays = MaxAuditRetentionDays
	}
	return nil
}

func applyEnv(c *Config) {
	if v := os.Getenv("RUD1_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if v := os.Getenv("RUD1_SERVER_HOST"); v != "" {
		c.Server.Host = v
	}
	if v := os.Getenv("RUD1_SERVER_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Server.Port = n
		}
	}
	if v := os.Getenv("RUD1_SERVER_TOKEN"); v != "" {
		c.Server.AuthToken = v
	}
	if v := os.Getenv("RUD1_CLOUD_ENABLED"); v != "" {
		c.Cloud.Enabled = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("RUD1_CLOUD_BASE_URL"); v != "" {
		c.Cloud.BaseURL = v
	}
	if v := os.Getenv("RUD1_CLOUD_API_SECRET"); v != "" {
		c.Cloud.APISecret = v
	}
	if v := os.Getenv("RUD1_CLOUD_REG_CODE"); v != "" {
		c.Cloud.RegistrationCode = v
	}
}
