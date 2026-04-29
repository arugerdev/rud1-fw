//go:build !linux

package serbridge

import "fmt"

// stubManager is the non-Linux build target. The firmware is a Pi-only
// product but tests and developer macOS/Windows builds still need
// `go build ./...` to compile, so we expose a Manager that refuses
// every Open with a clear "not implemented on this platform" error.
type stubManager struct{}

// NewLinuxManager keeps the same name across build tags so the agent
// bootstrap doesn't have to branch on GOOS at the call site. Returns
// a stub that fails Open() loudly.
func NewLinuxManager(_, _ int) (*stubManager, error) {
	return &stubManager{}, nil
}

func (s *stubManager) Start() error { return nil }
func (s *stubManager) Stop()        {}
func (s *stubManager) Open(busID string) (*Session, error) {
	return nil, fmt.Errorf("serial bridge: linux only (this is a %s build)", runtimeOS())
}
func (s *stubManager) Close(_ string) error           { return nil }
func (s *stubManager) Sessions() []Session             { return nil }
func (s *stubManager) SessionFor(_ string) *Session    { return nil }
func (s *stubManager) OpenBusIDs() []string            { return nil }
func (s *stubManager) Reset(_ string, _ int) error {
	return fmt.Errorf("serial bridge reset: linux only (this is a %s build)", runtimeOS())
}
