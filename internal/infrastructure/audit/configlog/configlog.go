// Package configlog implements a disk-backed, append-only JSONL audit log
// for runtime config mutations (timezone changes, NTP probe toggles,
// setup-wizard transitions, etc.).
//
// The shape mirrors the revlog package field-for-field at the rotation /
// retention level: one JSON object per line, daily rotation
// (audit-YYYY-MM-DD.jsonl) under a configurable base dir, fsync-per-write
// for crash safety, and size-bounded retention (default 14 days = two
// weeks). Reads are newest-first with a generously sized scanner buffer
// and skip malformed lines with a debug log so a single corrupt entry
// doesn't poison the history.
//
// The logger is intended for low-traffic operator-driven mutations
// (config flip-flops happen by hand or by automation a handful of times
// per day at most), so fsync-per-write is the right correctness/perf
// trade-off — same as revlog.
//
// A LoggerNoop is provided for the dev/test path where the agent has no
// writable base dir; callers can wire it unconditionally and get the
// same Append/List/Close interface without crashing.
package configlog

import (
	"bufio"
	"context"
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

// Entry is one line in the audit log. It is intentionally schema-light:
// `Previous` and `Next` are arbitrary JSON-serialisable values so the
// caller can record a small, mutation-specific diff without us defining
// a new type per action.
type Entry struct {
	At         int64  `json:"at"`                   // unix seconds
	Action     string `json:"action"`               // dotted, stable identifier
	Actor      string `json:"actor"`                // "operator" for BearerAuth callers
	ResourceID string `json:"resourceId,omitempty"` // optional, e.g. peer pubkey
	Previous   any    `json:"previous"`             // before-state or nil
	Next       any    `json:"next"`                 // after-state or nil
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
}

// ListOptions bounds and filters a List call. All zero values mean "no
// constraint" so callers can build a request incrementally.
type ListOptions struct {
	Limit  int
	Offset int
	Since  int64  // unix seconds, inclusive; 0 = no lower bound
	Until  int64  // unix seconds, inclusive; 0 = no upper bound
	Action string // exact action match; "" = any
}

// Options parameterises New. MaxFiles<=0 falls back to defaultMaxFiles
// (14 days). Now is injected for tests that simulate a date roll without
// waiting for the wall clock.
type Options struct {
	MaxFiles int
	Now      func() time.Time
}

// Logger is the abstract interface handlers depend on. The DiskLogger
// and LoggerNoop both satisfy it.
type Logger interface {
	Append(ctx context.Context, e Entry) error
	List(opts ListOptions) ([]Entry, error)
	Close() error
}

// DiskLogger is a thread-safe disk-backed audit log with daily rotation.
// Writes are append-only; rotation happens lazily on the first Append
// after a date change. A single in-process mutex guards both writers
// and the briefly-held snapshot of the directory listing.
type DiskLogger struct {
	mu       sync.Mutex
	baseDir  string
	maxFiles int

	// Lazy-opened day file. Nil until the first Append succeeds, so
	// construction can succeed even on a read-only base dir; the next
	// Append surfaces the error, callers can fall back to LoggerNoop.
	file    *os.File
	dateKey string // "2006-01-02" derived via now()

	// lastPruneAt records the wall-clock time of the most recent
	// successful prune attempt — exposed via Stats so the retention
	// endpoint can show operators when retention last converged. Zero
	// value means "no prune has run yet". Mutated under l.mu.
	lastPruneAt time.Time

	now func() time.Time
}

// filenamePrefix / filenameSuffix together build the per-day filename
// pattern (audit-YYYY-MM-DD.jsonl). Kept as constants so List can scan
// the directory with a simple HasPrefix / HasSuffix check.
const (
	filenamePrefix = "audit-"
	filenameSuffix = ".jsonl"

	// defaultMaxFiles keeps two weeks of history on disk by default.
	// Audit entries are tiny (a few hundred bytes) so 14 days is well
	// under any sensible rud1 disk budget.
	defaultMaxFiles = 14

	// maxScanLineSize matches revlog's bump past the default 64 KiB
	// scanner budget. Audit entries are small but Setup.notes can
	// contain arbitrary operator-supplied text, so we err on the side
	// of tolerating long lines rather than truncating.
	maxScanLineSize = 1 << 20

	// errorMaxLen is the truncation length for stored error strings.
	// Bigger errors are clipped with an ellipsis; newlines are
	// stripped because JSONL is one-record-per-line.
	errorMaxLen = 256
)

// New constructs a DiskLogger rooted at baseDir. The base dir is
// mkdir-p'd and an opportunistic prune runs so a long-stopped agent
// converges on retention bounds at startup. baseDir must be absolute
// or a clean relative path without traversal sequences — any ".." in
// the cleaned path is rejected outright.
func New(baseDir string, opts Options) (*DiskLogger, error) {
	cleaned := filepath.Clean(baseDir)
	if cleaned == "" || cleaned == "." {
		return nil, fmt.Errorf("configlog: empty baseDir")
	}
	for _, seg := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if seg == ".." {
			return nil, fmt.Errorf("configlog: baseDir must not contain traversal segments: %q", baseDir)
		}
	}
	maxFiles := opts.MaxFiles
	if maxFiles <= 0 {
		maxFiles = defaultMaxFiles
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(cleaned, 0o755); err != nil {
		return nil, fmt.Errorf("configlog: mkdir %q: %w", cleaned, err)
	}
	l := &DiskLogger{
		baseDir:  cleaned,
		maxFiles: maxFiles,
		now:      now,
	}
	if _, err := l.pruneOldLocked(); err != nil {
		// Non-fatal: the very next rotation will retry. Callers should
		// not have to handle a startup-only retention error.
		log.Debug().Err(err).Str("dir", cleaned).Msg("configlog: initial prune failed (non-fatal)")
	}
	return l, nil
}

// dayKey is the local-tz "YYYY-MM-DD" bucket key for a timestamp.
func dayKey(t time.Time) string { return t.Format("2006-01-02") }

// pathFor returns the absolute on-disk path for the given day key.
func (l *DiskLogger) pathFor(key string) string {
	return filepath.Join(l.baseDir, filenamePrefix+key+filenameSuffix)
}

// ensureOpenLocked opens (or rotates to) the file for `now`'s date.
// Must be called with l.mu held.
func (l *DiskLogger) ensureOpenLocked(now time.Time) error {
	key := dayKey(now)
	if l.file != nil && l.dateKey == key {
		return nil
	}
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	f, err := os.OpenFile(l.pathFor(key), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("configlog: open %q: %w", l.pathFor(key), err)
	}
	l.file = f
	l.dateKey = key
	if _, err := l.pruneOldLocked(); err != nil {
		log.Debug().Err(err).Msg("configlog: post-rotation prune failed (non-fatal)")
	}
	return nil
}

// Append serialises e and writes one line to today's file with fsync.
// The context is accepted for API symmetry / future cancellation but
// the disk write itself is not interruptible — audit writes finish
// fast (a few KiB at most) and we'd rather block briefly than drop a
// pending record.
func (l *DiskLogger) Append(_ context.Context, e Entry) error {
	if e.At == 0 {
		e.At = l.now().Unix()
	}
	e.Error = sanitiseError(e.Error)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if err := l.ensureOpenLocked(now); err != nil {
		return err
	}
	buf, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("configlog: marshal: %w", err)
	}
	buf = append(buf, '\n')
	if _, err := l.file.Write(buf); err != nil {
		return fmt.Errorf("configlog: write: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("configlog: sync: %w", err)
	}
	return nil
}

// listFiles returns the per-day filenames newest-first. Lexicographic
// ordering on YYYY-MM-DD is also chronological so a reverse string
// sort yields newest-first without parsing.
func (l *DiskLogger) listFiles() ([]string, error) {
	entries, err := os.ReadDir(l.baseDir)
	if err != nil {
		return nil, fmt.Errorf("configlog: readdir: %w", err)
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
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names, nil
}

// List walks the on-disk JSONL files newest-first, applies the filter
// window + action match, and returns a paginated slice. The mutex is
// held only briefly to snapshot the file path list — actual file I/O
// happens lock-free, mirroring revlog's pattern. This trades a small
// race window (a brand-new entry written during a long List can be
// missed) for read scalability; the audit log is not a database and
// callers should not depend on millisecond-level read consistency.
func (l *DiskLogger) List(opts ListOptions) ([]Entry, error) {
	l.mu.Lock()
	names, err := l.listFiles()
	baseDir := l.baseDir
	l.mu.Unlock()
	if err != nil {
		return nil, err
	}

	var all []Entry
	for _, name := range names {
		path := filepath.Join(baseDir, name)
		entries, err := readJSONLFile(path)
		if err != nil {
			log.Debug().Err(err).Str("path", path).Msg("configlog: file read failed, skipping")
			continue
		}
		// In-file order is chronological (oldest-first) because we
		// always append. Reverse so the cross-file concatenation is
		// globally newest-first.
		for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
			entries[i], entries[j] = entries[j], entries[i]
		}
		all = append(all, entries...)
	}

	// Filter window + action match.
	if opts.Since != 0 || opts.Until != 0 || opts.Action != "" {
		filtered := all[:0]
		for _, e := range all {
			if opts.Since != 0 && e.At < opts.Since {
				continue
			}
			if opts.Until != 0 && e.At > opts.Until {
				continue
			}
			if opts.Action != "" && e.Action != opts.Action {
				continue
			}
			filtered = append(filtered, e)
		}
		all = filtered
	}

	total := len(all)
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
	return out, nil
}

// Total is a helper that returns the unpaginated count for the given
// filter — useful for the HTTP handler that surfaces both the page and
// the total to the client. It walks the same files List walks; for
// the low-traffic audit path, the extra pass is acceptable.
func (l *DiskLogger) Total(opts ListOptions) (int, error) {
	// Re-use List with a sentinel limit so we don't re-implement the
	// filter logic. This is O(N) but the audit log is intentionally
	// small; we prefer a single source of truth over a tiny perf win.
	zeroPage := opts
	zeroPage.Limit = -1 // ignored: we want the count, not the page
	zeroPage.Offset = 0
	all, err := l.List(zeroPage)
	if err != nil {
		return 0, err
	}
	return len(all), nil
}

// readJSONLFile decodes one JSONL file. Each line is parsed
// independently; malformed lines are skipped with a debug log so one
// bad entry doesn't discard the rest of the file.
func readJSONLFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScanLineSize)

	var out []Entry
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			log.Debug().Err(err).Str("path", path).Msg("configlog: skipping malformed line")
			continue
		}
		out = append(out, e)
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// PruneOld is exposed so tests can assert retention directly. The
// regular path runs after every rotation. The returned count is the
// number of day-files actually removed; zero means the on-disk set
// already fit within the active retention window.
func (l *DiskLogger) PruneOld() (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pruneOldLocked()
}

// SetMaxFiles reconfigures the retention window in-place and returns
// the previous bound. Values <= 0 are coerced to the package default
// (mirrors New's behaviour) so callers can pass through a raw operator
// setting without their own clamp. Does NOT trigger a prune by itself —
// the caller decides whether shrinking warrants an immediate sweep.
func (l *DiskLogger) SetMaxFiles(n int) int {
	if n <= 0 {
		n = defaultMaxFiles
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := l.maxFiles
	l.maxFiles = n
	return prev
}

// MaxFiles returns the active retention bound. Used by handlers that
// need to compare a proposed retention against the live value before
// deciding whether to prune.
func (l *DiskLogger) MaxFiles() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.maxFiles
}

func (l *DiskLogger) pruneOldLocked() (int, error) {
	names, err := l.listFiles()
	if err != nil {
		return 0, err
	}
	l.lastPruneAt = l.now()
	if len(names) <= l.maxFiles {
		return 0, nil
	}
	toRemove := names[l.maxFiles:]
	removed := 0
	for _, n := range toRemove {
		p := filepath.Join(l.baseDir, n)
		if err := os.Remove(p); err != nil {
			log.Debug().Err(err).Str("path", p).Msg("configlog: prune remove failed")
			continue
		}
		removed++
	}
	return removed, nil
}

// Stats is the disk-inventory summary surfaced by the retention HTTP
// endpoint. ByteCount is best-effort — it sums file sizes via os.Stat
// and skips files we can't read. OldestEntryAt / NewestEntryAt /
// LastPruneAt are zero-valued when unknown; callers convert zero to a
// JSON-omitted pointer.
type Stats struct {
	TotalEntries  int
	TotalBytes    int64
	FileCount     int
	OldestEntryAt time.Time
	NewestEntryAt time.Time
	LastPruneAt   time.Time
}

// Stats walks the audit dir and returns a snapshot of on-disk usage.
// The mutex is briefly held to snapshot the file list and lastPruneAt;
// per-file I/O happens lock-free (same pattern as List).
func (l *DiskLogger) Stats() (Stats, error) {
	l.mu.Lock()
	names, err := l.listFiles()
	baseDir := l.baseDir
	lastPrune := l.lastPruneAt
	l.mu.Unlock()
	if err != nil {
		return Stats{}, err
	}

	out := Stats{LastPruneAt: lastPrune}
	if len(names) == 0 {
		return out, nil
	}

	out.FileCount = len(names)
	for _, name := range names {
		path := filepath.Join(baseDir, name)
		fi, err := os.Stat(path)
		if err != nil {
			log.Debug().Err(err).Str("path", path).Msg("configlog: stat failed, skipping in stats")
			continue
		}
		out.TotalBytes += fi.Size()
		entries, err := readJSONLFile(path)
		if err != nil {
			log.Debug().Err(err).Str("path", path).Msg("configlog: read failed, skipping in stats")
			continue
		}
		out.TotalEntries += len(entries)
	}

	// Filenames are newest-first (reverse-sorted YYYY-MM-DD), so the
	// last entry of the first file is the global newest and the first
	// entry of the last file is the global oldest. Falling back to the
	// file timestamp keeps us defensive if a day-file exists but its
	// content is unreadable / empty.
	if newest, ok := boundaryAt(filepath.Join(baseDir, names[0]), true); ok {
		out.NewestEntryAt = newest
	}
	if oldest, ok := boundaryAt(filepath.Join(baseDir, names[len(names)-1]), false); ok {
		out.OldestEntryAt = oldest
	}
	return out, nil
}

// boundaryAt returns the timestamp of the last (newest) or first
// (oldest) parseable entry in path. It silently falls back to the
// filename day key (00:00 UTC of that day) when the file is empty or
// unreadable so an in-progress / corrupt file doesn't blank out an
// otherwise valid window.
func boundaryAt(path string, last bool) (time.Time, bool) {
	entries, err := readJSONLFile(path)
	if err == nil && len(entries) > 0 {
		var pick Entry
		if last {
			pick = entries[len(entries)-1]
		} else {
			pick = entries[0]
		}
		if pick.At > 0 {
			return time.Unix(pick.At, 0).UTC(), true
		}
	}
	base := filepath.Base(path)
	if !strings.HasPrefix(base, filenamePrefix) || !strings.HasSuffix(base, filenameSuffix) {
		return time.Time{}, false
	}
	key := strings.TrimSuffix(strings.TrimPrefix(base, filenamePrefix), filenameSuffix)
	t, err := time.ParseInLocation("2006-01-02", key, time.UTC)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// Close flushes and releases the day-file handle. Safe on a nil
// receiver so shutdown paths can stay naive.
func (l *DiskLogger) Close() error {
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

// LoggerNoop is the no-op fallback used when the agent is running on a
// read-only filesystem or when the test harness wants to assert behaviour
// without touching disk. All methods succeed and discard their inputs.
type LoggerNoop struct{}

// Append discards the entry and returns nil.
func (LoggerNoop) Append(_ context.Context, _ Entry) error { return nil }

// List always returns an empty slice.
func (LoggerNoop) List(_ ListOptions) ([]Entry, error) { return nil, nil }

// Close always returns nil.
func (LoggerNoop) Close() error { return nil }

// Redact returns a shallow copy of m with values for sensitive keys
// replaced by the literal "[redacted]". Existing keys not in the
// blocklist are passed through. This is a defensive helper: none of
// the iter-30 handlers touch wifi.password / cellular.password / auth
// tokens directly, but Setup.notes is operator free-form text and we
// want a single, well-known place to plumb redaction through if and
// when those values ever appear.
//
// The function does NOT recurse; nested maps are passed through as-is
// (audit entries are flat by design).
func Redact(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	const sentinel = "[redacted]"
	blocked := map[string]struct{}{
		"password":      {},
		"wifi.password": {},
		"cellular.pin":  {},
		"cellular.password": {},
		"authtoken":     {},
		"auth_token":    {},
		"bearer":        {},
		"token":         {},
		"secret":        {},
		"apisecret":     {},
		"api_secret":    {},
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		key := strings.ToLower(k)
		if _, hit := blocked[key]; hit {
			out[k] = sentinel
			continue
		}
		out[k] = v
	}
	return out
}

// sanitiseError trims newlines and clips at errorMaxLen. Audit lines
// are JSONL — a stray '\n' would split one record into two malformed
// halves on the next read.
func sanitiseError(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > errorMaxLen {
		s = s[:errorMaxLen-3] + "..."
	}
	return s
}
