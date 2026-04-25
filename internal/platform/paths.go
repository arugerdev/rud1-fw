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

// BootIdentityPath returns the path where the device's code + PIN identity
// is persisted. The file is 0400 and lives on the FAT partition so it
// survives an OS reinstall as long as the SD card is physically preserved.
// Manufacturing can also pre-seed this file before shipping the device.
//
//   - Pi OS Bookworm+: /boot/firmware/rud1-identity.json (real FAT mount)
//   - Older Pi OS:     /boot/rud1-identity.json          (legacy FAT mount)
//   - Dev/simulated:   <DataDir>/rud1-identity.json      (easier to clear)
//   - Override:        $RUD1_IDENTITY_PATH
func BootIdentityPath() string {
	if env := os.Getenv("RUD1_IDENTITY_PATH"); env != "" {
		return env
	}
	if IsLinux() && !SimulateHardware() {
		// Pi OS Bookworm (2023+) and Trixie (2025+) mount the FAT at
		// /boot/firmware/. /boot/ on those images is just the ext4 root —
		// reinstalling the OS wipes it. Prefer the real FAT mount when
		// present; if a legacy file already lives at /boot/rud1-identity.json,
		// migrate by reading it (the caller in bootidentity.EnsureIdentity
		// just checks the path, so we keep using the FAT path going forward).
		if st, err := os.Stat("/boot/firmware"); err == nil && st.IsDir() {
			return "/boot/firmware/rud1-identity.json"
		}
		return "/boot/rud1-identity.json"
	}
	return filepath.Join(DataDir(), "rud1-identity.json")
}
