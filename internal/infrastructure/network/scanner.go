// Package netscanner reads host network interface state.
package netscanner

import (
	"bufio"
	"net"
	"os"
	"strings"
	"time"

	domainnet "github.com/rud1-es/rud1-fw/internal/domain/network"
	"github.com/rud1-es/rud1-fw/internal/platform"
)

// Scan returns the current network status of the host.
func Scan() (*domainnet.Status, error) {
	hostname, _ := os.Hostname()

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []domainnet.Interface
	for _, iface := range ifaces {
		di := domainnet.Interface{
			Name:       iface.Name,
			MAC:        iface.HardwareAddr.String(),
			MTU:        iface.MTU,
			Up:         iface.Flags&net.FlagUp != 0,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
			IsWireless: isWireless(iface.Name),
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				di.IPv4 = append(di.IPv4, ip4.String())
			} else {
				di.IPv6 = append(di.IPv6, ip.String())
			}
		}
		result = append(result, di)
	}

	gateway := ""
	dns := []string{}

	if !platform.SimulateHardware() {
		gateway = readGateway()
		dns = readDNS()
	}

	internet := checkInternet()

	return &domainnet.Status{
		Hostname:   hostname,
		Interfaces: result,
		Gateway:    gateway,
		DNS:        dns,
		Internet:   internet,
	}, nil
}

// isWireless returns true for interface names that indicate wireless adapters.
func isWireless(name string) bool {
	return strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "wlp")
}

// readGateway parses /proc/net/route to find the default gateway.
// Returns "" on any error or when running in simulate mode.
func readGateway() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Skip header line.
	scanner.Scan()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// fields: Iface Destination Gateway Flags ...
		if len(fields) < 3 {
			continue
		}
		// Default route: Destination == 00000000.
		if fields[1] != "00000000" {
			continue
		}
		// Gateway is a little-endian hex IPv4 address.
		gw := hexToIP(fields[2])
		if gw != "" {
			return gw
		}
	}
	return ""
}

// hexToIP converts a little-endian 8-char hex string (from /proc/net/route) to a dotted IPv4 string.
func hexToIP(hex string) string {
	if len(hex) != 8 {
		return ""
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		hi := hexNibble(hex[i*2])
		lo := hexNibble(hex[i*2+1])
		if hi < 0 || lo < 0 {
			return ""
		}
		b[i] = byte(hi<<4 | lo)
	}
	// Little-endian: byte order is reversed.
	return net.IPv4(b[3], b[2], b[1], b[0]).String()
}

func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// readDNS parses /etc/resolv.conf for nameserver lines.
func readDNS() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				servers = append(servers, fields[1])
			}
		}
	}
	return servers
}

// checkInternet attempts a TCP connection to Google's DNS to verify internet access.
func checkInternet() bool {
	conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
