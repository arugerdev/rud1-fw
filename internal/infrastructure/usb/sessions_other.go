//go:build !linux

package usblister

import "errors"

// Session mirrors the Linux-side definition so non-Linux builds compile.
type Session struct {
	BusID    string `json:"busId"`
	Status   int    `json:"status"`
	StatusOK bool   `json:"statusOk"`
	Attached bool   `json:"attached"`
	Shared   bool   `json:"shared"`
}

// ErrSessionsUnsupported is returned by SessionFor / ListSessions on non-Linux
// platforms where /sys/bus/usb/devices is not available. Handlers can inspect
// this to emit a 503 instead of a misleading 404.
var ErrSessionsUnsupported = errors.New("usbip sessions: not supported on this platform")

// ListSessions is a stub on non-Linux platforms.
func ListSessions() ([]Session, error) { return nil, nil }

// SessionFor is a stub on non-Linux platforms.
func SessionFor(busID string) (Session, error) {
	return Session{BusID: busID}, ErrSessionsUnsupported
}
