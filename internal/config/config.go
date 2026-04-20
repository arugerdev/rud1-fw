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
	LogLevel string       `yaml:"log_level"`
	Server   ServerConfig `yaml:"server"`
	Cloud    CloudConfig  `yaml:"cloud"`
	VPN      VPNConfig    `yaml:"vpn"`
	USB      USBConfig    `yaml:"usb"`
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
}

// USBConfig configures the USB-over-IP subsystem.
type USBConfig struct {
	BindPort        int      `yaml:"bind_port"`
	USBIPEnabled    bool     `yaml:"usbip_enabled"`
	AuthorizedNets  []string `yaml:"authorized_nets"` // CIDRs allowed to attach USB devices
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
			Interface:  "wg0",
			ConfigPath: filepath.Join(platform.ConfigDir(), "wg0.conf"),
		},
		USB: USBConfig{
			BindPort: 3240,
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
