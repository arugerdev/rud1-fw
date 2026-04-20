//go:build !linux

package sysinfo

// readReal falls back to simulation on non-Linux platforms.
func readReal() (*Metrics, error) {
	return simulate(), nil
}

// kernelVersion is not available on non-Linux platforms.
func kernelVersion() string { return "" }

// readNetworkBytes returns zeros on non-Linux platforms.
func readNetworkBytes() (rx, tx int64) { return 0, 0 }
