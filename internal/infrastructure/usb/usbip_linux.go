//go:build linux

package usblister

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

// USBIPServer manages the usbip daemon and device exports on Linux.
// It uses the userspace usbipd tool from the linux-tools package.
type USBIPServer struct {
	mu       sync.RWMutex
	exported map[string]bool // busId → exported
	cmd      *exec.Cmd
	port     int
}

var ipServerRe = regexp.MustCompile(`\s+(\d+-[\d.]+)\s+`)

// NewUSBIPServer returns a ready-to-use USBIPServer.
func NewUSBIPServer(port int) *USBIPServer {
	return &USBIPServer{
		exported: make(map[string]bool),
		port:     port,
	}
}

// Start launches the usbipd daemon listening on the configured port.
func (s *USBIPServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd != nil {
		return nil // already running
	}

	// usbipd -D --tcp-port <port>
	cmd := exec.Command("usbipd", "-D", "--tcp-port", fmt.Sprintf("%d", s.port))
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start usbipd: %w", err)
	}
	s.cmd = cmd
	return nil
}

// Stop kills the usbipd daemon gracefully.
func (s *USBIPServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd == nil {
		return
	}
	_ = s.cmd.Process.Kill()
	_ = s.cmd.Wait()
	s.cmd = nil
}

// Export binds a USB device for export via USB/IP. Idempotent: a second
// call against an already-exported bus id is a no-op rather than a
// `usbip bind` failure ("Device busy" / "already bound"). The desktop
// precall (rud1-desktop bindOnPi) issues this on every Attach click so
// the operator gets a one-click experience even when the device was
// bound by a prior session — the in-memory `s.exported` map covers
// agent-bound devices, and a stderr-level "already bound" probe covers
// devices the kernel still has bound from the previous run.
func (s *USBIPServer) Export(busId string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.exported[busId] {
		return nil
	}

	out, err := exec.Command("usbip", "bind", "-b", busId).CombinedOutput()
	if err != nil {
		// `usbip bind` returns non-zero when the device is already bound
		// to usbip-host (typical wording: "already bound to usbip-host"
		// or "Device busy"). Treat that as success: the kernel has the
		// state we asked for, the agent's bookkeeping was just stale.
		if isAlreadyBound(out) {
			s.exported[busId] = true
			return nil
		}
		return fmt.Errorf("usbip bind %s: %w — %s", busId, err, strings.TrimSpace(string(out)))
	}
	s.exported[busId] = true
	return nil
}

// isAlreadyBound recognises the stderr signatures `usbip bind` emits when
// the requested bus id is already attached to usbip-host. Both Debian
// (linux-tools-common) and Raspberry Pi OS (usbip package) variants are
// covered. Matching is case-insensitive and substring-based to absorb
// minor wording drift between kernel versions.
func isAlreadyBound(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "already bound") ||
		strings.Contains(s, "device busy") ||
		strings.Contains(s, "already exported")
}

// Unexport unbinds a USB device, removing it from USB/IP exports.
func (s *USBIPServer) Unexport(busId string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	out, err := exec.Command("usbip", "unbind", "-b", busId).CombinedOutput()
	if err != nil {
		return fmt.Errorf("usbip unbind %s: %w — %s", busId, err, strings.TrimSpace(string(out)))
	}
	delete(s.exported, busId)
	return nil
}

// ExportedDevices returns the list of currently exported bus IDs.
func (s *USBIPServer) ExportedDevices() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.exported))
	for id := range s.exported {
		ids = append(ids, id)
	}
	return ids
}

// ListExportable queries usbip list -l and returns bus IDs available for export.
func ListExportable() ([]string, error) {
	out, err := exec.Command("usbip", "list", "-l").Output()
	if err != nil {
		return nil, fmt.Errorf("usbip list: %w", err)
	}

	var busIDs []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		if m := ipServerRe.FindStringSubmatch(line); m != nil {
			busIDs = append(busIDs, strings.TrimSpace(m[1]))
		}
	}
	return busIDs, nil
}
