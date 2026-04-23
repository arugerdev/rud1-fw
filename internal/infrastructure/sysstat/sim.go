package sysstat

import "os"

// fillSimulated populates s with deterministic realistic numbers for
// development and Windows builds. Called from the Linux build path
// whenever platform.SimulateHardware() reports true (RUD1_SIMULATE=1) and
// unconditionally from the non-Linux build.
func fillSimulated(s *Stats) *Stats {
	if s.Hostname == "" {
		h, _ := os.Hostname()
		s.Hostname = h
	}
	if s.KernelVersion == "" {
		s.KernelVersion = "simulated"
	}
	s.Simulated = true

	// ~1 day uptime keeps the UI happy without looking freshly booted.
	s.Uptime = 86400
	s.LoadAvg1 = 0.5
	s.LoadAvg5 = 0.4
	s.LoadAvg15 = 0.3
	s.CPUUsage = 22.5

	const gib = int64(1) << 30
	s.MemTotal = 4 * gib
	s.MemAvailable = (6 * gib) / 10 // 60% free → 40% used
	s.MemFree = s.MemAvailable
	s.MemUsedPct = 40
	s.SwapTotal = gib
	s.SwapFree = gib

	s.DiskTotal = 32 * gib
	s.DiskFree = 32 * gib * 40 / 100 // 60% used
	s.DiskUsedPct = 60

	t := 45.0
	s.TempCPU = &t

	s.NetRxBytes = 123_456_789
	s.NetTxBytes = 45_678_901

	return s
}
