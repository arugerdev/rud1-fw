// Package auditcursor persists the heartbeat audit-shipping cursor across
// agent reboots.
//
// The cursor is the unix-second timestamp of the newest audit-log entry the
// agent has successfully shipped to the cloud. On the next heartbeat the
// agent ships only entries with `at > cursor`, capped at MaxHBAuditEntries
// per tick. Cloud already de-dupes by (deviceId, at, action, hash), so the
// cursor is purely a local optimisation: it lowers the noise floor on
// chatty Pis and prevents the rolling-window from losing entries when a
// device has been offline through more than 16 mutations.
//
// The on-disk shape is a tiny JSON object with a single RFC3339 timestamp:
//
//	{"lastShippedAt": "2026-04-25T12:00:00Z"}
//
// Kept deliberately separate from the bootidentity payload (single
// responsibility — the cursor is reset on factory wipe but the boot
// identity is not) and from the runtime device-store (which is a domain
// concern, not an infra one).
package auditcursor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// fileShape is the JSON wire format. Versioned so a future schema change
// can be detected by older agents and ignored gracefully.
type fileShape struct {
	Version       int       `json:"version"`
	LastShippedAt time.Time `json:"lastShippedAt"`
}

const fileVersion = 1

// FileName is the on-disk basename. Kept exported so tests and the agent
// can compose the absolute path without duplicating the constant.
const FileName = "audit-cursor.json"

// Store is a thread-safe persistent cursor. Reads and writes are
// serialised by an internal mutex; the on-disk file is rewritten
// atomically (write to .tmp + rename) so a crash mid-write cannot
// corrupt the cursor.
type Store struct {
	path string

	mu     sync.Mutex
	cached time.Time // last value successfully read or committed
	loaded bool      // whether `cached` reflects a real load attempt
}

// New builds a cursor store rooted at the given directory. The directory
// is mkdir-p'd so callers can rely on construction succeeding even on
// first boot. A non-empty `path` is otherwise unconstrained — callers
// typically pass `platform.DataDir()`.
func New(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("auditcursor: empty dir")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("auditcursor: mkdir %q: %w", dir, err)
	}
	return &Store{path: filepath.Join(dir, FileName)}, nil
}

// Path returns the absolute path of the cursor file. Useful for logging
// and for tests that want to assert the on-disk presence/absence.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Load returns the persisted cursor.
//
// The boolean return distinguishes the *first-boot* case (file genuinely
// missing — `(zero, false, nil)`) from a *normal* read (`(t, true, nil)`).
// The agent uses this distinction to default to time.Now() on first boot
// of an upgraded agent, instead of zero — otherwise we'd spam-ship the
// entire on-disk audit history once on the first heartbeat after upgrade.
//
// Malformed files are surfaced as an error rather than silently treated
// as "missing" — corruption deserves operator attention. A wrong-version
// file is also returned as an error so a newer-than-expected schema
// doesn't get clobbered with a stale value.
func (s *Store) Load() (time.Time, bool, error) {
	if s == nil {
		return time.Time{}, false, errors.New("auditcursor: nil store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.loaded = true
			s.cached = time.Time{}
			return time.Time{}, false, nil
		}
		return time.Time{}, false, fmt.Errorf("auditcursor: read %q: %w", s.path, err)
	}
	var f fileShape
	if err := json.Unmarshal(data, &f); err != nil {
		return time.Time{}, false, fmt.Errorf("auditcursor: parse %q: %w", s.path, err)
	}
	if f.Version != fileVersion {
		return time.Time{}, false, fmt.Errorf("auditcursor: unsupported version %d in %q", f.Version, s.path)
	}
	s.loaded = true
	s.cached = f.LastShippedAt.UTC()
	return s.cached, true, nil
}

// Commit persists `at` as the new cursor value. The on-disk write is
// atomic via tmp+rename so a crash never leaves the file half-written.
// The in-memory cache is updated only on successful disk write.
//
// `at` is normalised to UTC so the on-disk RFC3339 form is always
// timezone-stable across agent restarts in different TZs.
func (s *Store) Commit(at time.Time) error {
	if s == nil {
		return errors.New("auditcursor: nil store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	at = at.UTC()
	f := fileShape{Version: fileVersion, LastShippedAt: at}
	data, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		return fmt.Errorf("auditcursor: marshal: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("auditcursor: write tmp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		// Best-effort cleanup so a botched rename doesn't leave a dangling
		// .tmp file forever; ignore the cleanup error since the rename
		// failure is the actionable one.
		_ = os.Remove(tmp)
		return fmt.Errorf("auditcursor: rename: %w", err)
	}
	s.loaded = true
	s.cached = at
	return nil
}
