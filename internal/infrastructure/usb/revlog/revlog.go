// Package revlog implements a disk-backed, append-only JSONL revocation log
// with daily rotation and size-bounded retention.
//
// Each USB/IP policy or unplug revocation is written as one JSON object per
// line into a file named revocations-YYYY-MM-DD.jsonl under the configured
// base directory (typically /var/lib/rud1/revocations on production Pis, or
// a temp dir on simulated hardware). Writes are flushed to disk with Sync
// after each Append so revocations survive a hard power cut, trading a
// little I/O for correctness — revocation traffic is low enough (hand-edited
// policies, occasional unplug events) that fsync-per-write is not a concern.
//
// The reader parses files newest-first with a bufio.Scanner (MaxScanTokenSize
// bumped so pathological long JSON lines don't truncate) and returns a
// newest-first paginated slice. Malformed lines are skipped with a debug log
// so a single corrupt entry doesn't poison the whole history.
//
// The on-disk Entry shape mirrors handlers.RevocationEntry field-for-field
// (same JSON field tags) so callers can translate at the package boundary
// without pulling the handlers import into infrastructure and creating a
// cycle.
package revlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Entry mirrors handlers.RevocationEntry field-for-field with identical JSON
// tags so the on-disk format stays stable across package boundaries. The
// handlers package translates between its own type and this one at the edge.
type Entry struct {
	BusID       string `json:"busId"`
	VendorID    string `json:"vendorId,omitempty"`
	ProductID   string `json:"productId,omitempty"`
	Serial      string `json:"serial,omitempty"`
	VendorName  string `json:"vendorName,omitempty"`
	ProductName string `json:"productName,omitempty"`
	Reason      string `json:"reason"`
	At          int64  `json:"at"` // unix seconds
}

// ListOptions controls the window and pagination of a List call. Since/Until
// are inclusive bounds in unix seconds; zero means "no bound". Offset is
// applied after filtering; Limit<=0 returns everything past the offset.
type ListOptions struct {
	Limit  int
	Offset int
	Since  int64 // unix seconds, inclusive; 0 = no lower bound
	Until  int64 // unix seconds, inclusive; 0 = no upper bound
}

// Logger is a thread-safe disk-backed revocation log with daily rotation.
//
// Append serialises entries one per line to the current day's JSONL file,
// rotating when the local-tz date changes and pruning the oldest files so
// at most maxFiles days of history are retained on disk. List reads all
// files newest-first and applies the caller's filter + pagination.
type Logger struct {
	mu       sync.Mutex
	baseDir  string
	maxFiles int

	// Current day's open file. Nil until the first Append (lazy open so
	// construction can succeed even if the dir is read-only — Append will
	// fail loudly and the caller can fall back to in-memory only).
	file    *os.File
	dateKey string // "2006-01-02" in the logger's time zone (derived via now())

	// now is injected for tests that want to simulate a date rollover
	// without waiting for the wall clock to tick.
	now func() time.Time
}

// filenamePrefix is the stable prefix for per-day JSONL files. Kept as a
// constant so List can scan the dir with a single HasPrefix check.
const filenamePrefix = "revocations-"
const filenameSuffix = ".jsonl"

// maxScanLineSize is the upper bound on a single JSON line the reader will
// accept. Entries are small (a few hundred bytes at most) but very long
// product/vendor names coming from a device descriptor could theoretically
// exceed the default 64 KiB Scanner budget — so we pre-allocate 1 MiB which
// is comfortably above any realistic entry.
const maxScanLineSize = 1 << 20

// New creates (or opens) a Logger rooted at baseDir with the given retention.
// It mkdir -p's the base dir (0755) and runs one PruneOld on startup so a
// crash that left the disk over-quota converges on the next boot. If the
// dir can't be created the error is returned — the caller is expected to
// fall back to in-memory-only logging.
func New(baseDir string, maxFiles int) (*Logger, error) {
	if maxFiles <= 0 {
		maxFiles = 30
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, fmt.Errorf("revlog: mkdir %q: %w", baseDir, err)
	}
	l := &Logger{
		baseDir:  baseDir,
		maxFiles: maxFiles,
		now:      time.Now,
	}
	// Opportunistic prune so a restart after a long downtime doesn't leave
	// stale files around. A failure here is non-fatal: a subsequent
	// rotation will retry.
	if err := l.pruneOldLocked(); err != nil {
		log.Debug().Err(err).Str("dir", baseDir).Msg("revlog: initial prune failed (non-fatal)")
	}
	return l, nil
}

// dayKey returns the "YYYY-MM-DD" bucket for t in local time.
func dayKey(t time.Time) string { return t.Format("2006-01-02") }

// pathFor returns the absolute JSONL file path for the given day key.
func (l *Logger) pathFor(key string) string {
	return filepath.Join(l.baseDir, filenamePrefix+key+filenameSuffix)
}

// ensureOpenLocked opens (creating if necessary) the current day's file,
// rotating if the date has changed since the last call. Must be called with
// l.mu held.
func (l *Logger) ensureOpenLocked(now time.Time) error {
	key := dayKey(now)
	if l.file != nil && l.dateKey == key {
		return nil
	}
	// Rotate: close the previous handle, open the new day's file append-only.
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	f, err := os.OpenFile(l.pathFor(key), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("revlog: open %q: %w", l.pathFor(key), err)
	}
	l.file = f
	l.dateKey = key
	// Prune after every rotation so retention stays bounded even on a
	// long-running agent that never restarts.
	if err := l.pruneOldLocked(); err != nil {
		log.Debug().Err(err).Msg("revlog: post-rotation prune failed (non-fatal)")
	}
	return nil
}

// Append serialises e as JSON, writes one line to today's file, and fsync's
// so the entry survives a hard power cut. Callers may mutate e after return.
func (l *Logger) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if err := l.ensureOpenLocked(now); err != nil {
		return err
	}
	buf, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("revlog: marshal: %w", err)
	}
	buf = append(buf, '\n')
	if _, err := l.file.Write(buf); err != nil {
		return fmt.Errorf("revlog: write: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("revlog: sync: %w", err)
	}
	return nil
}

// listFiles returns all revocations-YYYY-MM-DD.jsonl files under baseDir,
// sorted newest-first by date key.
func (l *Logger) listFiles() ([]string, error) {
	entries, err := os.ReadDir(l.baseDir)
	if err != nil {
		return nil, fmt.Errorf("revlog: readdir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasPrefix(n, filenamePrefix) || !strings.HasSuffix(n, filenameSuffix) {
			continue
		}
		names = append(names, n)
	}
	// Lexicographic sort on YYYY-MM-DD is also chronological, so descending
	// sort yields newest-first.
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names, nil
}

// List reads all JSONL files newest-first, applies Since/Until filters, and
// returns a paginated slice plus the unpaginated filter total. Malformed
// lines are skipped (debug-logged) so a single corrupted entry doesn't
// fail the whole query.
func (l *Logger) List(opts ListOptions) ([]Entry, int, error) {
	l.mu.Lock()
	names, err := l.listFiles()
	baseDir := l.baseDir
	l.mu.Unlock()
	if err != nil {
		return nil, 0, err
	}

	// We read files newest-first; within each file the JSONL append order is
	// chronological (oldest-first). To get a globally newest-first slice we
	// reverse each file's entries as we concatenate.
	var all []Entry
	for _, name := range names {
		path := filepath.Join(baseDir, name)
		entries, err := readJSONLFile(path)
		if err != nil {
			log.Debug().Err(err).Str("path", path).Msg("revlog: file read failed, skipping")
			continue
		}
		// Reverse in place so newest-first order is preserved when we append.
		for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
			entries[i], entries[j] = entries[j], entries[i]
		}
		all = append(all, entries...)
	}

	// Apply Since/Until window. Both are inclusive so the UI "last 24h"
	// filter can pass Since=now-86400 without fencepost games.
	if opts.Since != 0 || opts.Until != 0 {
		filtered := all[:0]
		for _, e := range all {
			if opts.Since != 0 && e.At < opts.Since {
				continue
			}
			if opts.Until != 0 && e.At > opts.Until {
				continue
			}
			filtered = append(filtered, e)
		}
		all = filtered
	}

	total := len(all)

	// Pagination — offset past end yields empty slice, limit<=0 means "all
	// remaining" so callers can request unbounded listings.
	start := opts.Offset
	if start < 0 {
		start = 0
	}
	if start > total {
		start = total
	}
	end := total
	if opts.Limit > 0 {
		end = start + opts.Limit
		if end > total {
			end = total
		}
	}
	out := make([]Entry, end-start)
	copy(out, all[start:end])
	return out, total, nil
}

// readJSONLFile parses one JSONL file into a slice of Entries. Each line is
// decoded independently; malformed lines are skipped with a debug log so
// one bad entry doesn't discard the whole file.
func readJSONLFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Bump the scanner buffer past the default 64 KiB; entries are tiny in
	// practice but an unusually long product name from a device descriptor
	// could exceed it, and we prefer to tolerate rather than truncate.
	scanner.Buffer(make([]byte, 0, 64*1024), maxScanLineSize)

	var out []Entry
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			log.Debug().Err(err).Str("path", path).Msg("revlog: skipping malformed line")
			continue
		}
		out = append(out, e)
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// PruneOld deletes oldest files beyond maxFiles so disk use stays bounded.
// Called opportunistically after every rotation; also exposed so tests can
// assert retention directly.
func (l *Logger) PruneOld() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pruneOldLocked()
}

// pruneOldLocked is PruneOld's body, to be called with l.mu already held.
func (l *Logger) pruneOldLocked() error {
	names, err := l.listFiles()
	if err != nil {
		return err
	}
	if len(names) <= l.maxFiles {
		return nil
	}
	// names is newest-first; everything past maxFiles is eligible for
	// deletion. Errors removing one file don't abort the whole sweep.
	toRemove := names[l.maxFiles:]
	for _, n := range toRemove {
		p := filepath.Join(l.baseDir, n)
		if err := os.Remove(p); err != nil {
			log.Debug().Err(err).Str("path", p).Msg("revlog: prune remove failed")
		}
	}
	return nil
}

// Close flushes and releases the current file handle. Safe to call multiple
// times and on a nil *Logger so shutdown paths can be naive.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
