// Package storage implements file-based persistence for agent state.
package storage

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/rud1-es/rud1-fw/internal/domain/device"
	"github.com/rud1-es/rud1-fw/internal/platform"
)

// ErrNoIdentity is returned by Load when no identity file exists yet.
var ErrNoIdentity = errors.New("no device identity stored")

// DeviceStore persists the device Identity as a JSON file on disk.
type DeviceStore struct {
	mu   sync.RWMutex
	path string
}

// NewDeviceStore creates a DeviceStore that writes to platform.DataDir()/device.json.
func NewDeviceStore() *DeviceStore {
	return &DeviceStore{path: filepath.Join(platform.DataDir(), "device.json")}
}

// Load reads the identity from disk. Returns ErrNoIdentity if the file does not exist.
func (s *DeviceStore) Load() (*device.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoIdentity
		}
		return nil, err
	}

	var id device.Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, err
	}
	return &id, nil
}

// Save writes the identity to disk atomically (write to .tmp then rename).
func (s *DeviceStore) Save(id *device.Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := platform.EnsureDir(filepath.Dir(s.path)); err != nil {
		return err
	}

	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Clear deletes the identity file from disk.
func (s *DeviceStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := os.Remove(s.path)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}
