//go:build linux

package sysstat

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rud1-es/rud1-fw/internal/platform"
)

// defaultRootPath is the filesystem the disk metrics are reported for.
// Keeping it a function so simulated builds can override without rebuilding
// the call site.
func defaultRootPath() string { return "/" }

// populate fills in every best-effort field. Never returns a non-nil error
// today — reserved so callers can keep the two-value signature stable if we
// later surface a catastrophic failure mode.
func (c *Collector) populate(ctx context.Context, s *Stats) (*Stats, error) {
	if platform.SimulateHardware() {
		return fillSimulated(s), nil
	}

	hostname, _ := os.Hostname()
	s.Hostname = hostname
	s.KernelVersion = readKernelVersion()

	s.Uptime = readUptime()
	s.LoadAvg1, s.LoadAvg5, s.LoadAvg15 = readLoadAvg()
	s.CPUUsage = readCPUUsage(ctx)

	memTotal, memFree, memAvail, swapTotal, swapFree := readMemInfo()
	s.MemTotal = memTotal
	s.MemFree = memFree
	s.MemAvailable = memAvail
	if memTotal > 0 {
		s.MemUsedPct = 100.0 * float64(memTotal-memAvail) / float64(memTotal)
	}
	s.SwapTotal = swapTotal
	s.SwapFree = swapFree

	dTotal, dFree := readDisk(s.RootPath)
	s.DiskTotal = dTotal
	s.DiskFree = dFree
	if dTotal > 0 {
		s.DiskUsedPct = 100.0 * float64(dTotal-dFree) / float64(dTotal)
	}

	if t, ok := readCPUTemp(); ok {
		s.TempCPU = &t
	}

	s.NetRxBytes, s.NetTxBytes = readNetBytes()
	return s, nil
}

// readKernelVersion parses /proc/version for the kernel release string.
func readKernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		return fields[2]
	}
	return strings.TrimSpace(string(data))
}

// readUptime parses /proc/uptime and returns the integer seconds.
func readUptime() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int64(f)
}

// readLoadAvg parses /proc/loadavg → 1/5/15-minute averages.
func readLoadAvg() (float64, float64, float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	la1, _ := strconv.ParseFloat(fields[0], 64)
	la5, _ := strconv.ParseFloat(fields[1], 64)
	la15, _ := strconv.ParseFloat(fields[2], 64)
	return la1, la5, la15
}

// readCPUUsage samples /proc/stat twice 250 ms apart and returns the
// delta-based utilisation. Respects ctx cancellation during the sleep —
// a cancelled context short-circuits to 0 so the snapshot still resolves.
func readCPUUsage(ctx context.Context) float64 {
	idle1, total1, err := parseCPUStat()
	if err != nil {
		return 0
	}

	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return 0
	case <-timer.C:
	}

	idle2, total2, err := parseCPUStat()
	if err != nil {
		return 0
	}
	dIdle := idle2 - idle1
	dTotal := total2 - total1
	if dTotal == 0 {
		return 0
	}
	pct := 100.0 * float64(dTotal-dIdle) / float64(dTotal)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct
}

func parseCPUStat() (idle, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return 0, 0, fmt.Errorf("unexpected /proc/stat format")
		}
		var vals [10]uint64
		for i := 1; i < len(fields) && i <= 10; i++ {
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			vals[i-1] = v
			total += v
		}
		idle = vals[3]
		return idle, total, nil
	}
	return 0, 0, fmt.Errorf("/proc/stat: cpu line not found")
}

// readMemInfo parses /proc/meminfo → memTotal/Free/Available + swap
// (all in bytes).
func readMemInfo() (memTotal, memFree, memAvail, swapTotal, swapFree int64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseInt(fields[1], 10, 64)
		// meminfo reports kB — convert to bytes.
		valBytes := val * 1024
		switch fields[0] {
		case "MemTotal:":
			memTotal = valBytes
		case "MemFree:":
			memFree = valBytes
		case "MemAvailable:":
			memAvail = valBytes
		case "SwapTotal:":
			swapTotal = valBytes
		case "SwapFree:":
			swapFree = valBytes
		}
	}
	return
}

// readDisk returns (total, free) bytes for the given path via statfs.
func readDisk(path string) (int64, int64) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0
	}
	total := int64(st.Blocks) * int64(st.Bsize)
	free := int64(st.Bfree) * int64(st.Bsize)
	return total, free
}

// readCPUTemp reads /sys/class/thermal/thermal_zone0/temp (milli-Celsius).
// Returns (value, true) on success, (_, false) when the file is unavailable
// (non-Pi hardware, locked down kernel, etc.).
func readCPUTemp() (float64, bool) {
	data, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp")
	if err != nil {
		return 0, false
	}
	raw := strings.TrimSpace(string(data))
	milli, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return float64(milli) / 1000.0, true
}

// readNetBytes sums rx/tx from /proc/net/dev across every non-loopback
// interface. Matches the semantics of sysinfo.readNetworkBytes so the
// numbers stay comparable across the two packages.
func readNetBytes() (int64, int64) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Header lines.
	scanner.Scan()
	scanner.Scan()

	var rx, tx int64
	for scanner.Scan() {
		line := scanner.Text()
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:colon])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 9 {
			continue
		}
		r, err1 := strconv.ParseInt(fields[0], 10, 64)
		t, err2 := strconv.ParseInt(fields[8], 10, 64)
		if err1 == nil && err2 == nil {
			rx += r
			tx += t
		}
	}
	return rx, tx
}
