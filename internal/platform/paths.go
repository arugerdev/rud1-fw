package platform

import (
	"os"
	"path/filepath"
)

// DataDir returns the directory where the agent stores its mutable state
// (registration identity, cached config, local SQLite db if any).
//
//   - Linux production:  /var/lib/rud1-agent
//   - Windows dev:       %LOCALAPPDATA%\Rud1\agent
//   - Fallback:          ./data next to the binary
func DataDir() string {
	if env := os.Getenv("RUD1_DATA_DIR"); env != "" {
		return env
	}
	if IsLinux() && !SimulateHardware() {
		return "/var/lib/rud1-agent"
	}
	if IsWindows() {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, "Rud1", "agent")
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "data"
	}
	return filepath.Join(cwd, "data")
}

// ConfigDir returns the directory where YAML configs live.
//
//   - Linux production:  /etc/rud1-agent
//   - Windows dev:       %APPDATA%\Rud1\agent
//   - Fallback:          ./configs
func ConfigDir() string {
	if env := os.Getenv("RUD1_CONFIG_DIR"); env != "" {
		return env
	}
	if IsLinux() && !SimulateHardware() {
		return "/etc/rud1-agent"
	}
	if IsWindows() {
		if base := os.Getenv("APPDATA"); base != "" {
			return filepath.Join(base, "Rud1", "agent")
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "configs"
	}
	return filepath.Join(cwd, "configs")
}

// LogDir returns the directory where the agent writes rotating logs.
func LogDir() string {
	if env := os.Getenv("RUD1_LOG_DIR"); env != "" {
		return env
	}
	if IsLinux() && !SimulateHardware() {
		return "/var/log/rud1-agent"
	}
	return filepath.Join(DataDir(), "logs")
}

// EnsureDir creates the directory (and any missing parents) with mode 0o755.
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0o755)
}
