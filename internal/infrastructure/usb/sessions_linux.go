//go:build linux

package usblister

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Session is the live USB/IP state for a single bus ID as exposed by the
// kernel via /sys/bus/usb/devices/<busid>/usbip_status.
//
// Status values (as documented in Documentation/usb/usbip_protocol.rst):
//   0 = SDEV_ST_AVAILABLE    — device not claimed by usbip
//   1 = SDEV_ST_USED         — claimed (bound) but no client attached
//   2 = SDEV_ST_ERROR        — error
//   3 = SDEV_ST_USED_CONNECT — remote client is actively attached
type Session struct {
	BusID    string `json:"busId"`
	Status   int    `json:"status"`
	StatusOK bool   `json:"statusOk"` // false when usbip_status can't be read
	Attached bool   `json:"attached"` // true iff status == 3
	Shared   bool   `json:"shared"`   // true iff status in {1, 3}
}

// ListSessions reads usbip_status for every bus ID under /sys/bus/usb/devices.
// Returns one Session per non-hub USB device.
func ListSessions() ([]Session, error) {
	devs, err := listLinux()
	if err != nil {
		return nil, err
	}
	sessions := make([]Session, 0, len(devs))
	for _, d := range devs {
		sessions = append(sessions, readSession(d.BusID))
	}
	return sessions, nil
}

// SessionFor returns the live USB/IP status for a single bus ID.
func SessionFor(busID string) (Session, error) {
	if _, err := os.Stat(filepath.Join("/sys/bus/usb/devices", busID)); err != nil {
		return Session{BusID: busID}, fmt.Errorf("usbip_status: %w", err)
	}
	return readSession(busID), nil
}

func readSession(busID string) Session {
	sess := Session{BusID: busID}
	raw, err := os.ReadFile(filepath.Join("/sys/bus/usb/devices", busID, "usbip_status"))
	if err != nil {
		return sess
	}
	val, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return sess
	}
	sess.Status = val
	sess.StatusOK = true
	sess.Shared = val == 1 || val == 3
	sess.Attached = val == 3
	return sess
}
