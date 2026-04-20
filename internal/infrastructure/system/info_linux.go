//go:build linux

package sysinfo

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// readReal reads metrics from Linux /proc and /sys.
func readReal() (*Metrics, error) {
	m := &Metrics{}

	cpu, err := readCPU()
	if err != nil {
		cpu = 0
	}
	m.CPUUsage = cpu

	total, avail, err := readMemInfo()
	if err == nil && total > 0 {
		m.TotalMemMB = total / 1024
		m.FreeMemMB = avail / 1024
		m.MemoryUsage = 100.0 * float64(total-avail) / float64(total)
	}

	m.Temperature = readTemperature()
	m.DiskUsage, _ = readDiskUsage("/")
	m.Uptime, _ = readUptime()
	m.RxBytes, m.TxBytes = readNetworkBytes()

	return m, nil
}

// readCPU reads /proc/stat twice 100 ms apart and returns delta utilisation.
func readCPU() (float64, error) {
	idle1, total1, err := parseCPUStat()
	if err != nil {
		return 0, err
	}
	time.Sleep(100 * time.Millisecond)
	idle2, total2, err := parseCPUStat()
	if err != nil {
		return 0, err
	}

	deltaIdle := idle2 - idle1
	deltaTotal := total2 - total1
	if deltaTotal == 0 {
		return 0, nil
	}
	return 100.0 * float64(deltaTotal-deltaIdle) / float64(deltaTotal), nil
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
		idle = vals[3] // column 4 = idle
		return idle, total, nil
	}
	return 0, 0, fmt.Errorf("/proc/stat: cpu line not found")
}

// readMemInfo parses /proc/meminfo; returns total and available kB.
func readMemInfo() (total, available uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = val
		case "MemAvailable:":
			available = val
		}
		if total > 0 && available > 0 {
			break
		}
	}
	return total, available, nil
}

// readTemperature reads the thermal zone temp in Celsius (returns 0 on error).
func readTemperature() float64 {
	data, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp")
	if err != nil {
		return 0
	}
	raw := strings.TrimSpace(string(data))
	milliC, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0
	}
	return float64(milliC) / 1000.0
}

// readDiskUsage uses syscall.Statfs to compute percent used on the given path.
func readDiskUsage(path string) (float64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	totalBytes := stat.Blocks * uint64(stat.Bsize)
	freeBytes := stat.Bfree * uint64(stat.Bsize)
	if totalBytes == 0 {
		return 0, nil
	}
	return 100.0 * float64(totalBytes-freeBytes) / float64(totalBytes), nil
}

// readUptime parses /proc/uptime and returns seconds.
func readUptime() (int64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty /proc/uptime")
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return int64(f), nil
}

// kernelVersion reads the first word of /proc/version (e.g. "Linux"),
// then the version field, returning e.g. "6.1.21-v8+".
func kernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return ""
	}
	// Format: "Linux version 6.1.21-v8+ (builder@...) ..."
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		return fields[2]
	}
	return strings.TrimSpace(string(data))
}

// readNetworkBytes sums rx/tx bytes from /proc/net/dev across all
// non-loopback interfaces.
func readNetworkBytes() (rx, tx int64) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Skip the two header lines.
	scanner.Scan()
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		// Format: "  eth0:   12345 ..."
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:colon])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		// fields[0] = rx bytes, fields[8] = tx bytes
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
