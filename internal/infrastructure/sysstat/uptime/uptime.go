// Package uptime implements a small disk-backed ring of system lifecycle
// events — boots, shutdowns, and agent restarts — so the diagnostics UI can
// tell "sustained warnings" apart from "warnings clustered around a crash".
//
// The store mirrors the revlog package's on-disk conventions (JSONL,
// fsync-per-write, atomic tmp+rename rewrite) but keeps a single file rather
// than per-day rotation: the event rate is on the order of one append per
// reboot, so a 200-entry cap is plenty and a ring layout keeps queries cheap.
//
// Events are written one per line as
//
//	{"at":"2026-04-23T12:00:00Z","kind":"boot","uptimeSeconds":0,"reason":""}
//
// and List() returns them newest-first for easy UI consumption.
package uptime

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/platform"
)

// maxEvents is the ring-buffer cap. Enough to cover ~half a year of daily
// reboots plus the occasional agent restart; cheap to scan on startup.
const maxEvents = 200

// eventsFilename is the on-disk JSONL file name (under the store's base dir).
const eventsFilename = "uptime-events.jsonl"

// bootIDFilename is the sidecar that persists the last-seen boot_id across
// agent restarts so DetectBootEvent can tell a reboot from a simple agent
// restart.
const bootIDFilename = "uptime-bootid.txt"

// kernelBootIDPath is the canonical source of the current kernel boot id.
// Exposed as a var (not const) so tests can point it at a fixture.
var kernelBootIDPath = "/proc/sys/kernel/random/boot_id"

// procUptimePath is read by DetectBootEvent to attach the current system
// uptime to a boot event. Exposed as a var for the same reason.
var procUptimePath = "/proc/uptime"

// Event is one lifecycle row. Kind is one of "boot", "shutdown", "restart".
// Reason is free-form (shutdown paths fill it with the upstream error string;
// a plain graceful shutdown leaves it empty).
type Event struct {
	At      time.Time     `json:"at"`
	Kind    string        `json:"kind"`
	Uptime  time.Duration `json:"-"`
	Reason  string        `json:"reason"`
}

// diskEvent is the on-disk encoding. We split Uptime into its own field so
// JSON consumers see a plain integer seconds value rather than a Go-encoded
// nanoseconds int64.
type diskEvent struct {
	At            time.Time `json:"at"`
	Kind          string    `json:"kind"`
	UptimeSeconds int64     `json:"uptimeSeconds"`
	Reason        string    `json:"reason"`
}

func (e Event) toDisk() diskEvent {
	return diskEvent{
		At:            e.At.UTC(),
		Kind:          e.Kind,
		UptimeSeconds: int64(e.Uptime.Seconds()),
		Reason:        e.Reason,
	}
}

func (d diskEvent) toEvent() Event {
	return Event{
		At:     d.At,
		Kind:   d.Kind,
		Uptime: time.Duration(d.UptimeSeconds) * time.Second,
		Reason: d.Reason,
	}
}

// Store is the thread-safe disk-backed ring of Events.
type Store struct {
	mu     sync.Mutex
	dir    string
	path   string
	events []diskEvent // oldest-first in memory; List reverses for output
	closed bool
}

// DefaultDir returns the canonical on-disk location for the uptime store.
// On simulated hardware it's under OS temp so Windows dev tests run without
// touching /var/lib.
func DefaultDir() string {
	if platform.SimulateHardware() {
		return filepath.Join(os.TempDir(), "rud1-uptime")
	}
	return "/var/lib/rud1/uptime"
}

// OpenStore opens (or creates) the store rooted at DefaultDir(). A failure
// to mkdir or read the existing file is surfaced to the caller — the agent
// wires it as non-fatal so a read-only disk still boots.
func OpenStore() (*Store, error) {
	return OpenStoreAt(DefaultDir())
}

// OpenStoreAt is OpenStore with an explicit directory. Used by tests so they
// can point at t.TempDir() without relying on SimulateHardware.
func OpenStoreAt(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("uptime: mkdir %q: %w", dir, err)
	}
	s := &Store{
		dir:  dir,
		path: filepath.Join(dir, eventsFilename),
	}
	if err := s.load(); err != nil {
		// Starting fresh on a corrupt file is safer than refusing to boot —
		// the next Append will rewrite cleanly.
		log.Warn().Err(err).Str("path", s.path).Msg("uptime: load failed, starting empty")
		s.events = nil
	}
	return s, nil
}

// load reads the on-disk JSONL into s.events. Missing file is treated as an
// empty store. Malformed lines are skipped with a debug log.
func (s *Store) load() error {
	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.events = nil
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var out []diskEvent
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e diskEvent
		if err := json.Unmarshal(line, &e); err != nil {
			log.Debug().Err(err).Str("path", s.path).Msg("uptime: skipping malformed line")
			continue
		}
		out = append(out, e)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	// Defensive tail-clip in case a previous process crashed before its
	// rewrite. The on-disk file could also legitimately contain up to maxEvents
	// rows — we only clip strictly above that.
	if len(out) > maxEvents {
		out = out[len(out)-maxEvents:]
	}
	s.events = out
	return nil
}

// Append records one event, trimming to maxEvents if needed. A fresh rewrite
// is performed on overflow so the file mirrors the in-memory slice exactly.
func (s *Store) Append(ev Event) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("uptime: store closed")
	}
	// Fill the timestamp defensively — a caller that passes a zero time
	// probably meant "now" and a stamp is required for ordering.
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	de := ev.toDisk()

	s.events = append(s.events, de)

	// Overflow path: rewrite-on-trim to keep the file in sync with the ring.
	if len(s.events) > maxEvents {
		s.events = s.events[len(s.events)-maxEvents:]
		return s.rewriteLocked()
	}

	// Fast path: single-line append + fsync.
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("uptime: open: %w", err)
	}
	defer f.Close()
	buf, err := json.Marshal(de)
	if err != nil {
		return fmt.Errorf("uptime: marshal: %w", err)
	}
	buf = append(buf, '\n')
	if _, err := f.Write(buf); err != nil {
		return fmt.Errorf("uptime: write: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("uptime: sync: %w", err)
	}
	return nil
}

// rewriteLocked serialises s.events to a tmp file and renames onto the real
// path atomically. Assumes s.mu is held.
func (s *Store) rewriteLocked() error {
	tmp, err := os.CreateTemp(s.dir, eventsFilename+".*")
	if err != nil {
		return fmt.Errorf("uptime: tmp create: %w", err)
	}
	tmpPath := tmp.Name()
	writer := bufio.NewWriter(tmp)
	for _, e := range s.events {
		buf, err := json.Marshal(e)
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
			return fmt.Errorf("uptime: marshal: %w", err)
		}
		buf = append(buf, '\n')
		if _, err := writer.Write(buf); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
			return fmt.Errorf("uptime: tmp write: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("uptime: tmp flush: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("uptime: tmp sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("uptime: tmp close: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("uptime: rename: %w", err)
	}
	return nil
}

// List returns at most `limit` events newest-first. A non-positive limit
// returns everything held.
func (s *Store) List(limit int) []Event {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.events)
	if n == 0 {
		return nil
	}
	// Determine how many to emit.
	want := n
	if limit > 0 && limit < want {
		want = limit
	}
	out := make([]Event, 0, want)
	// Reverse-iterate to yield newest-first without mutating the backing
	// slice.
	for i := n - 1; i >= 0 && len(out) < want; i-- {
		out = append(out, s.events[i].toEvent())
	}
	return out
}

// Size is the current event count. Exposed for tests + future diagnostics.
func (s *Store) Size() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// Close marks the store closed and drops the in-memory slice. Subsequent
// Appends return an error. Safe to call on a nil receiver.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// ReadStoredBootID returns the boot_id we last saw during DetectBootEvent.
// Absent file → empty string + nil error. Used by the agent to pass the
// previous value into DetectBootEvent on startup.
func ReadStoredBootID() (string, error) {
	return readStoredBootIDAt(DefaultDir())
}

func readStoredBootIDAt(dir string) (string, error) {
	p := filepath.Join(dir, bootIDFilename)
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// WriteStoredBootID persists the current boot_id so a later agent restart
// can detect whether the kernel actually rebooted in between.
func WriteStoredBootID(id string) error {
	return writeStoredBootIDAt(DefaultDir(), id)
}

func writeStoredBootIDAt(dir, id string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, bootIDFilename), []byte(id+"\n"), 0o644)
}

// readCurrentBootID reads /proc/sys/kernel/random/boot_id. Returns empty
// string on any error or non-Linux platforms — callers treat that as "unable
// to detect" rather than "boot changed".
func readCurrentBootID() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	data, err := os.ReadFile(kernelBootIDPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// readProcUptime parses /proc/uptime ("<seconds_since_boot> <idle>") and
// returns the first column as a duration. Non-Linux → zero.
func readProcUptime() time.Duration {
	if runtime.GOOS != "linux" {
		return 0
	}
	data, err := os.ReadFile(procUptimePath)
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return time.Duration(secs * float64(time.Second))
}

// DetectBootEvent returns a "boot" event when the kernel boot_id differs
// from prevBootID (or when prevBootID is empty, i.e. first-ever startup).
// Under SimulateHardware it returns (Event{}, false) — we never synthesise
// boot events in simulated environments.
//
// The caller is expected to persist the new boot_id via WriteStoredBootID
// after appending the returned event, so a subsequent agent restart without
// a kernel reboot correctly reports nothing.
func DetectBootEvent(prevBootID string) (Event, bool) {
	if platform.SimulateHardware() {
		return Event{}, false
	}
	current := readCurrentBootID()
	if current == "" {
		// Can't read /proc — no decision possible, don't synthesise.
		return Event{}, false
	}
	if prevBootID != "" && prevBootID == current {
		// Agent restart on the same kernel boot — not a boot event.
		return Event{}, false
	}
	return Event{
		At:     time.Now().UTC(),
		Kind:   "boot",
		Uptime: readProcUptime(),
		Reason: "",
	}, true
}

// CurrentBootID exposes the current kernel boot_id so the agent can persist
// it after appending the detected event. Empty on non-Linux or read error.
func CurrentBootID() string { return readCurrentBootID() }
