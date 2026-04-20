// Package platform exposes runtime-environment helpers so the rest of
// the codebase can make decisions based on the current OS without
// sprinkling build tags everywhere.
package platform

import (
	"os"
	"runtime"
	"strings"
)

// OS returns the current operating system name ("linux", "windows", etc.).
func OS() string { return runtime.GOOS }

// Arch returns the current CPU architecture ("amd64", "arm64", "arm", etc.).
func Arch() string { return runtime.GOARCH }

// IsLinux reports whether the agent is running on Linux.
func IsLinux() bool { return runtime.GOOS == "linux" }

// IsWindows reports whether the agent is running on Windows.
func IsWindows() bool { return runtime.GOOS == "windows" }

// IsRaspberryPi makes a best-effort guess based on /proc/device-tree/model.
// It only makes sense on Linux; on other OSes it always returns false.
func IsRaspberryPi() bool {
	if !IsLinux() {
		return false
	}
	data, err := os.ReadFile("/proc/device-tree/model")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), "raspberry pi")
}

// SimulateHardware reports whether the agent should stub out hardware
// interactions (WireGuard, usbip, systemd) with in-memory fakes.
//
// This is always true on Windows, and can be forced on Linux via the
// RUD1_SIMULATE=1 environment variable for local development.
func SimulateHardware() bool {
	if IsWindows() {
		return true
	}
	v := strings.TrimSpace(os.Getenv("RUD1_SIMULATE"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}
