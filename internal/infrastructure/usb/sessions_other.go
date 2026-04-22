//go:build !linux

package usblister

// Session mirrors the Linux-side definition so non-Linux builds compile.
type Session struct {
	BusID    string `json:"busId"`
	Status   int    `json:"status"`
	StatusOK bool   `json:"statusOk"`
	Attached bool   `json:"attached"`
	Shared   bool   `json:"shared"`
}

// ListSessions is a stub on non-Linux platforms.
func ListSessions() ([]Session, error) { return nil, nil }

// SessionFor is a stub on non-Linux platforms.
func SessionFor(busID string) (Session, error) {
	return Session{BusID: busID}, nil
}
