package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Save writes the current Config as YAML to c.Path atomically.
//
// The write is done via a temp file in the same directory followed by an
// os.Rename, so a crash mid-write cannot leave a half-written file. On
// POSIX the rename is atomic; on Windows it atomically replaces the target
// when it exists.
//
// YAML comments in the original file are NOT preserved (go-yaml has no
// round-trip marshaller that keeps them). The zero-value struct fields
// are emitted with their Go defaults. This is acceptable because the
// config schema is fully owned by the agent and the file is intended to
// be edited via the API from now on (the local panel's policy editor).
func (c *Config) Save() error {
	if c.Path == "" {
		return fmt.Errorf("config: Save requires Path to be set")
	}
	if err := c.Validate(); err != nil {
		return fmt.Errorf("config: refusing to save invalid config: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}

	dir := filepath.Dir(c.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("config: mkdir %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".config.yaml.*")
	if err != nil {
		return fmt.Errorf("config: create tmp: %w", err)
	}
	tmpPath := tmp.Name()

	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("config: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("config: sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("config: close tmp: %w", err)
	}
	// Best-effort: preserve mode of existing file; fall back to 0640.
	mode := os.FileMode(0o640)
	if st, err := os.Stat(c.Path); err == nil {
		mode = st.Mode().Perm()
	}
	_ = os.Chmod(tmpPath, mode)

	if err := os.Rename(tmpPath, c.Path); err != nil {
		cleanup()
		return fmt.Errorf("config: rename into place: %w", err)
	}
	return nil
}
