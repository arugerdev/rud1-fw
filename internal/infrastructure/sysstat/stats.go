// Package sysstat collects rich, point-in-time host statistics for the
// rud1-agent. It is complementary to the older `sysinfo` package:
// `sysinfo.Metrics` is a small subset kept for backwards compatibility with
// existing handlers / heartbeats, while `sysstat.Stats` is the full payload
// served by the `/api/system/stats` endpoint and embedded in heartbeats as
// an optional `HBSystem` block.
//
// All collection is best-effort: a failure to read a single data point
// (temperature sensor unavailable, /proc/net/dev missing a column) returns
// a zero value for that field rather than failing the whole snapshot. Only
// a catastrophic problem (e.g. unable to allocate) surfaces as an error.
//
// On simulated hardware (Windows or RUD1_SIMULATE=1), Snapshot returns
// deterministic realistic values so local development and UI work does not
// depend on the host OS.
package sysstat

import (
	"context"
	"runtime"
	"time"
)

// Stats is a point-in-time snapshot of the host system.
//
// Field naming mirrors the JSON camelCase the handler emits; the struct
// tag forces consistent serialisation when the same struct is embedded in
// the heartbeat payload.
type Stats struct {
	// Identity / platform
	Hostname      string `json:"hostname"`
	Platform      string `json:"platform"`
	Arch          string `json:"arch"`
	KernelVersion string `json:"kernelVersion,omitempty"`
	Simulated     bool   `json:"simulated"`

	// Uptime (seconds)
	Uptime int64 `json:"uptime"`

	// CPU
	CPUCount  int     `json:"cpuCount"`
	LoadAvg1  float64 `json:"loadAvg1"`
	LoadAvg5  float64 `json:"loadAvg5"`
	LoadAvg15 float64 `json:"loadAvg15"`
	CPUUsage  float64 `json:"cpuUsage"` // 0..100 %, instantaneous

	// Memory (bytes)
	MemTotal     int64   `json:"memTotal"`
	MemFree      int64   `json:"memFree"`
	MemAvailable int64   `json:"memAvailable"`
	MemUsedPct   float64 `json:"memUsedPct"`

	SwapTotal int64 `json:"swapTotal"`
	SwapFree  int64 `json:"swapFree"`

	// Disk (bytes) — reported for RootPath.
	DiskTotal   int64   `json:"diskTotal"`
	DiskFree    int64   `json:"diskFree"`
	DiskUsedPct float64 `json:"diskUsedPct"`
	RootPath    string  `json:"rootPath"`

	// Temperature (Celsius). Nullable: the Pi exposes it via the thermal
	// zone sysfs; other hardware / simulated mode may omit it.
	TempCPU *float64 `json:"tempCpu,omitempty"`

	// Network (cumulative bytes across non-loopback interfaces).
	NetRxBytes int64  `json:"netRxBytes"`
	NetTxBytes int64  `json:"netTxBytes"`
	NetIface   string `json:"netIface,omitempty"`

	// Timestamp the snapshot was captured (RFC3339 UTC).
	CapturedAt string `json:"capturedAt"`
}

// Collector takes snapshots of the host. A single Collector instance is
// safe to share across goroutines (the only mutable state is the CPU /
// network delta cache, both of which would merely lose one sample on
// concurrent use — never crash).
//
// Uplink is the network interface name to report in Stats.NetIface. It's
// purely informational; byte totals always sum across every non-loopback
// interface so the cloud can graph actual bandwidth without having to
// know which interface is "up" right now. The agent passes
// lan.DetectDefaultUplink() at construction time; empty string is fine.
type Collector struct {
	Uplink string
}

// Snapshot collects the current system stats, respecting ctx for the CPU
// sampling sleep. A cancelled context returns a partial snapshot with
// CPUUsage=0 rather than an error — the heartbeat loop must not be
// blocked by a slow /proc read.
func (c *Collector) Snapshot(ctx context.Context) (*Stats, error) {
	if c == nil {
		c = &Collector{}
	}
	s := &Stats{
		Platform:   runtime.GOOS,
		Arch:       runtime.GOARCH,
		CPUCount:   runtime.NumCPU(),
		RootPath:   defaultRootPath(),
		NetIface:   c.Uplink,
		CapturedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return c.populate(ctx, s)
}
