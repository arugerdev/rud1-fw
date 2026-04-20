// Package sysinfo reads host system metrics (CPU, memory, temperature, disk, uptime).
// On simulated hardware it returns randomised but plausible values.
package sysinfo

import (
	"math/rand"

	"github.com/rud1-es/rud1-fw/internal/platform"
)

// Metrics holds a point-in-time snapshot of host resource usage.
type Metrics struct {
	CPUUsage    float64 // 0–100 %
	MemoryUsage float64 // 0–100 %
	Temperature float64 // Celsius; 0 if unavailable
	DiskUsage   float64 // 0–100 %, root partition
	Uptime      int64   // seconds
	FreeMemMB   uint64
	TotalMemMB  uint64
	RxBytes     int64 // cumulative received bytes (all non-loopback ifaces)
	TxBytes     int64 // cumulative transmitted bytes (all non-loopback ifaces)
}

// Read collects current system metrics.
// On simulated hardware (Windows or RUD1_SIMULATE=1) it returns fake values.
func Read() (*Metrics, error) {
	if platform.SimulateHardware() {
		return simulate(), nil
	}
	return readReal()
}

// KernelVersion returns the OS kernel version string (e.g. "6.1.21-v8+").
// Returns an empty string if unavailable or on non-Linux platforms.
func KernelVersion() string {
	return kernelVersion()
}

// simulate returns random but realistic metrics for development / Windows.
func simulate() *Metrics {
	totalMB := uint64(4096)
	cpu := 15.0 + rand.Float64()*30.0
	memPct := 40.0 + rand.Float64()*20.0
	temp := 42.0 + rand.Float64()*10.0
	disk := 35.0 + rand.Float64()*20.0
	uptime := int64(3600) + int64(rand.Intn(86400))
	freeMB := uint64(float64(totalMB) * (1 - memPct/100))

	return &Metrics{
		CPUUsage:    cpu,
		MemoryUsage: memPct,
		Temperature: temp,
		DiskUsage:   disk,
		Uptime:      uptime,
		FreeMemMB:   freeMB,
		TotalMemMB:  totalMB,
		RxBytes:     int64(rand.Intn(1_000_000_000)),
		TxBytes:     int64(rand.Intn(200_000_000)),
	}
}
