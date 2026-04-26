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
	"compress/gzip"
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	// gzipSuffix is appended to a rotated day-file's full filename
	// (e.g. `audit-2026-04-23.jsonl.gz`). Iter 41 introduced
	// transparent gzip compression of rotated archives so a long-lived
	// box with 14-day retention does not balloon disk usage holding
	// uncompressed JSONL — historical audit entries compress 8-15x
	// because they are repetitive structured text. The active day-file
	// (today's writer) stays uncompressed; rotation is the trigger.
	gzipSuffix = ".gz"

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

	// maxCompressionDays caps the size of the iter-44 CompressionByDay
	// histogram. The cloud-side outlier dashboard only needs a recent
	// window — typical retention defaults are 14 days, today's hardest
	// fleet ceiling is ~30 days, so 90 leaves comfortable headroom for
	// future retention growth while bounding the heartbeat payload. When
	// the on-disk archive exceeds this bound (e.g. after retention is
	// raised retroactively), the newest days are kept and older ones
	// drop off the histogram. Aggregates (TotalBytes/EntryBytes/
	// FileCount/TotalEntries) are unaffected — only the histogram is
	// trimmed.
	maxCompressionDays = 90
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
	// Iter 43: sweep orphan `.gz.tmp` files left behind when a previous
	// process crashed mid-compression (see compressArchivedFile in iter
	// 41 for the atomic write→rename flow that produces these). Today
	// the next rotation truncates any leftover via `O_TRUNC`, but a
	// long-lived agent that doesn't rotate again (e.g. powered down for
	// weeks then booted on the same calendar day) would keep the orphan
	// indefinitely. Cheap glob, best-effort removal — a single failure
	// must not block construction.
	sweepOrphanGzipTmps(cleaned)
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

// sweepOrphanGzipTmps removes any `*.gz.tmp` files in baseDir. These
// are produced by compressArchivedFile (iter 41) as the intermediate
// target before the atomic rename to `.gz`; a crash between
// `os.OpenFile(tmp, ...)` and `os.Rename(tmp, dst)` leaves the partial
// file behind. We log each reaped file at info level so an operator
// reviewing boot logs can see what was cleaned. Removal failures are
// logged at warn level and do not abort the sweep — the next rotation
// will still truncate the orphan via O_TRUNC.
func sweepOrphanGzipTmps(baseDir string) {
	pattern := filepath.Join(baseDir, "*"+gzipSuffix+".tmp")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		// filepath.Glob only fails on malformed patterns — our pattern
		// is a constant-derived literal, so this is truly defensive.
		log.Warn().Err(err).Str("dir", baseDir).Msg("configlog: orphan .gz.tmp glob failed; skipping startup sweep")
		return
	}
	for _, p := range matches {
		var size int64
		if fi, statErr := os.Stat(p); statErr == nil {
			size = fi.Size()
		}
		if err := os.Remove(p); err != nil {
			log.Warn().Err(err).Str("path", p).Int64("size", size).Msg("configlog: failed to remove orphan .gz.tmp; will be truncated on next rotation")
			continue
		}
		log.Info().Str("path", p).Int64("size", size).Msg("configlog: reaped orphan .gz.tmp from crashed rotation")
	}
}

// dayKey is the local-tz "YYYY-MM-DD" bucket key for a timestamp.
func dayKey(t time.Time) string { return t.Format("2006-01-02") }

// pathFor returns the absolute on-disk path for the given day key.
func (l *DiskLogger) pathFor(key string) string {
	return filepath.Join(l.baseDir, filenamePrefix+key+filenameSuffix)
}

// ensureOpenLocked opens (or rotates to) the file for `now`'s date.
// Must be called with l.mu held.
//
// Iter 41: when this rotates from one day to the next (i.e. an existing
// open file is closed because the date key changed), the previous
// day-file is gzip-compressed in place. Compression is best-effort —
// failures (disk full, EPERM) leave the original `.jsonl` intact so the
// next rotation can retry. The active writer never compresses; only
// archived day-files do.
func (l *DiskLogger) ensureOpenLocked(now time.Time) error {
	key := dayKey(now)
	if l.file != nil && l.dateKey == key {
		return nil
	}
	// Capture the day key of the file we're about to close so we can
	// archive it after the close. This is only set when we actually
	// had an open file (i.e. an in-process rotation, not the first
	// open since New()).
	var prevKey string
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
		prevKey = l.dateKey
	}
	f, err := os.OpenFile(l.pathFor(key), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("configlog: open %q: %w", l.pathFor(key), err)
	}
	l.file = f
	l.dateKey = key
	if prevKey != "" && prevKey != key {
		// Best-effort: a gzip failure must not fail the rotation. The
		// new active file is already open; the worst case is one extra
		// uncompressed day-file on disk until the next rotation.
		if err := compressArchivedFile(l.pathFor(prevKey)); err != nil {
			log.Warn().Err(err).Str("path", l.pathFor(prevKey)).Msg("configlog: gzip of rotated day-file failed; leaving original intact")
		}
	}
	if _, err := l.pruneOldLocked(); err != nil {
		log.Debug().Err(err).Msg("configlog: post-rotation prune failed (non-fatal)")
	}
	return nil
}

// compressArchivedFile gzips `src` to `src.gz` atomically (write to
// `src.gz.tmp` then rename) and removes the original on success. If any
// step fails, the original `src` is left untouched and any partial
// `src.gz.tmp` is best-effort cleaned. A pre-existing `src.gz` is
// overwritten by the rename — this is safe because the source content
// is what we just produced; a leftover `.gz.tmp` from a prior crash is
// also overwritten (truncate on open).
//
// If `src` does not exist (e.g. a same-day "rotation" with no entries
// yet, or a previous rotation already archived it), returns nil so
// the caller can stay naive.
func compressArchivedFile(src string) error {
	in, err := os.Open(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open source: %w", err)
	}
	// We close `in` explicitly (not via defer) before os.Remove(src) so
	// Windows — which refuses to delete an open handle — can drop the
	// inode. Posix wouldn't mind either way; the explicit close costs
	// nothing.

	dst := src + gzipSuffix
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		_ = in.Close()
		return fmt.Errorf("create tmp: %w", err)
	}
	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		_ = gz.Close()
		_ = out.Close()
		_ = in.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("gzip copy: %w", err)
	}
	if err := gz.Close(); err != nil {
		_ = out.Close()
		_ = in.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("gzip close: %w", err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = in.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("fsync tmp: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = in.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := in.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close source: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	// At this point `dst` is durable. Removing the source is what makes
	// the archival "in place"; if the remove fails (e.g. EPERM after a
	// container remount), the on-disk state is still correct — the next
	// PruneOld will see two filenames for the same day and take care of
	// it eventually. Log so an operator can notice repeated misses.
	if err := os.Remove(src); err != nil {
		log.Warn().Err(err).Str("path", src).Msg("configlog: gzip succeeded but source removal failed; both files now on disk")
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

// listFiles returns the per-day filenames newest-first. Iter 41
// includes both `.jsonl` (today's active file plus any pre-iter-41
// archive that hasn't been re-rotated yet) and `.jsonl.gz` (compressed
// archives produced on rotation). Sorting is by the embedded YYYY-MM-DD
// day key — both `.jsonl` and `.jsonl.gz` for the same day collapse to
// identical day keys, but in normal operation only one variant exists
// per day so the lexical reverse sort is still chronological.
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
		if !isAuditFile(n) {
			continue
		}
		names = append(names, n)
	}
	// Sort by day key descending so newest comes first. We can't rely
	// on plain reverse-string sort across mixed suffixes because
	// `audit-2026-04-23.jsonl` < `audit-2026-04-23.jsonl.gz`
	// lexically; collapsing both to the same day key keeps cross-file
	// ordering correct in the (rare) overlap case.
	sort.Slice(names, func(i, j int) bool {
		return dayKeyFromName(names[i]) > dayKeyFromName(names[j])
	})
	return names, nil
}

// isAuditFile reports whether `name` is one of the configlog day-file
// variants: `audit-YYYY-MM-DD.jsonl` (active or pre-iter-41 archive)
// or `audit-YYYY-MM-DD.jsonl.gz` (post-iter-41 compressed archive).
func isAuditFile(name string) bool {
	if !strings.HasPrefix(name, filenamePrefix) {
		return false
	}
	return strings.HasSuffix(name, filenameSuffix) ||
		strings.HasSuffix(name, filenameSuffix+gzipSuffix)
}

// dayKeyFromName extracts the YYYY-MM-DD portion of an audit filename.
// Returns "" for inputs that don't match the expected pattern; callers
// should pre-filter via isAuditFile.
func dayKeyFromName(name string) string {
	trimmed := strings.TrimPrefix(name, filenamePrefix)
	trimmed = strings.TrimSuffix(trimmed, gzipSuffix)
	trimmed = strings.TrimSuffix(trimmed, filenameSuffix)
	return trimmed
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
//
// Iter 41: paths ending in `.gz` are transparently decompressed via
// `compress/gzip`. The wrapper is created lazily so the stat/open cost
// for plain `.jsonl` files is unchanged.
func readJSONLFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, gzipSuffix) {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("configlog: gzip reader %q: %w", path, err)
		}
		defer gz.Close()
		r = gz
	}

	scanner := bufio.NewScanner(r)
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
//
// Iter 41 split the byte accounting in two:
//   - TotalBytes is the on-disk footprint (gzip-compressed bytes for
//     archived day-files, raw bytes for the still-active file). This
//     is what operators see in `du` and what the cloud heartbeat
//     reports as `auditTotalBytes`.
//   - EntryBytes is the sum of raw (uncompressed) JSONL bytes — useful
//     for sizing the export endpoint and for showing operators the
//     compression ratio. Best-effort: if a `.gz` file fails to
//     decompress, that file's contribution is dropped from EntryBytes
//     but its TotalBytes is still counted.
//
// Iter 44 adds CompressionByDay: a per-day {dayKey -> ratio} map
// (entryBytes/totalBytes) that lets the cloud render outliers — e.g.
// a single huge low-entropy day skewing the fleet-wide average from
// `computeFleetCompressionRatio` (rud1-es iter 43). Entries are only
// emitted for days where real compression happened (entryBytes >
// totalBytes AND both non-zero), matching the physical-regime gates in
// the cloud's `formatCompressionRatio`. A plain `.jsonl` file (the
// active day, or a pre-iter-41 archive) has entryBytes==totalBytes and
// thus contributes no entry — ratio 1.0 means "no compression" which
// is not useful signal. A malformed `.gz` whose entries can't be
// re-marshalled also contributes no entry, mirroring the existing
// EntryBytes drop behaviour.
type Stats struct {
	TotalEntries     int
	TotalBytes       int64
	EntryBytes       int64
	FileCount        int
	OldestEntryAt    time.Time
	NewestEntryAt    time.Time
	LastPruneAt      time.Time
	CompressionByDay map[string]float64
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
	// Iter 47: hold the per-day compression ratios in a heap-backed cap
	// container during the walk so eviction at maxCompressionDays is
	// O(log N) instead of the iter-46 O(N) lex-min scan. Flattened to
	// the public Stats.CompressionByDay map at the end of the walk.
	dayCap := newCompressionDayCap(maxCompressionDays)
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
		// EntryBytes is the uncompressed JSONL footprint. For a plain
		// `.jsonl` file that's just the on-disk size; for a `.jsonl.gz`
		// archive we re-marshal each entry to estimate what the line
		// occupied pre-gzip. This is approximate (whitespace/escape
		// differences vs. the original encoder) but stays within ~1%
		// for the structured shapes audit emits.
		var fileEntryBytes int64
		if strings.HasSuffix(name, gzipSuffix) {
			for i := range entries {
				if buf, err := json.Marshal(entries[i]); err == nil {
					fileEntryBytes += int64(len(buf)) + 1 // trailing \n
				}
			}
		} else {
			fileEntryBytes = fi.Size()
		}
		out.EntryBytes += fileEntryBytes

		// Iter 44: emit a per-day ratio entry only when real
		// compression happened — entryBytes strictly greater than
		// totalBytes and both non-zero. This matches the cloud's
		// `formatCompressionRatio` physical-regime gates and excludes
		// plain `.jsonl` files (where entryBytes == totalBytes,
		// ratio==1.0, no useful signal) as well as days where the
		// re-marshal estimate dropped to zero (malformed gzip whose
		// entries can't be parsed back into Entry shapes).
		//
		// Iter 45: cap the histogram at maxCompressionDays. Aggregates
		// above (TotalBytes/EntryBytes/FileCount/TotalEntries) are NOT
		// affected by this cap; they remain a full inventory of on-disk
		// state.
		//
		// Iter 46: switch from "stop adding once full" to "evict oldest
		// when at cap" via the day-keyed cap helper. Iter 47: back the
		// cap with a min-heap so eviction is O(log N) per insert rather
		// than O(N) lex-min scan. Behaviour pinned: smallest YYYY-MM-DD
		// evicted; an incoming day older than every existing key is
		// dropped to preserve the "newest N kept" guarantee under any
		// iteration order.
		if fileEntryBytes > 0 && fi.Size() > 0 && fileEntryBytes > fi.Size() {
			day := dayKeyFromName(name)
			if day != "" {
				dayCap.add(day, float64(fileEntryBytes)/float64(fi.Size()))
			}
		}
	}
	out.CompressionByDay = dayCap.snapshot()

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

// compressionDayCap is a bounded {day -> ratio} aggregator that keeps
// the newest `cap` distinct YYYY-MM-DD keys. When an `add` would push
// the size past `cap`, the lexicographically-smallest key (which is
// also the chronologically oldest, since day keys are fixed-width
// YYYY-MM-DD) is evicted. An incoming key older than every existing
// key is dropped instead — the same "refuse to evict ourselves" guard
// the iter-46 helper had, which is what makes the contract sort-order
// independent.
//
// Iter 47: the eviction is backed by a min-heap of day strings so the
// per-insert cost when at cap is O(log N) instead of the iter-46 O(N)
// lex-min scan. At today's N=90 the wall-clock difference is in the
// noise, but raising `maxCompressionDays` into the thousands (or
// invoking `Stats()` more frequently — heartbeat cadence is currently
// every ~30s but a future hot path could run it per-request) becomes
// a real cost as the scan is N per insert past cap.
//
// The container is internal to the configlog package; callers consume
// the snapshot via `snapshot()` which materialises the map so the
// public Stats.CompressionByDay shape is unchanged.
type compressionDayCap struct {
	capacity int
	m        map[string]float64
	h        compressionDayHeap
}

// newCompressionDayCap returns a fresh cap container. capacity <= 0
// makes every `add` a no-op so callers never need to special-case
// "uncapped".
func newCompressionDayCap(capacity int) *compressionDayCap {
	return &compressionDayCap{capacity: capacity}
}

// add inserts (day -> ratio). If `day` already exists, the value is
// updated in place and the heap is untouched (size is unchanged so no
// eviction is needed). When the insert would exceed capacity, the
// lex-smallest key is evicted via Pop — but only if the incoming key
// is strictly larger; otherwise the incoming key is dropped because
// evicting itself would weaken the "newest capacity kept" guarantee.
func (c *compressionDayCap) add(day string, ratio float64) {
	if c == nil || c.capacity <= 0 {
		return
	}
	if c.m == nil {
		c.m = make(map[string]float64, c.capacity)
		// Pre-size the heap backing slice so the typical fill-to-cap
		// path avoids slice-growth reallocations entirely.
		c.h = make(compressionDayHeap, 0, c.capacity)
	}
	if _, exists := c.m[day]; exists {
		c.m[day] = ratio
		return
	}
	if len(c.m) >= c.capacity {
		// Peek the heap min — guaranteed non-empty because len(m)>=cap>0.
		oldest := c.h[0]
		if day < oldest {
			// Incoming key is older than every existing entry; drop
			// it instead of evicting a newer day. This is the
			// regression-resistance guard the iter-46 contract pinned.
			return
		}
		// O(log N) removal of the heap min.
		_ = heap.Pop(&c.h)
		delete(c.m, oldest)
	}
	c.m[day] = ratio
	heap.Push(&c.h, day)
}

// snapshot returns the contained map, transferring ownership to the
// caller. Subsequent `add` calls allocate a fresh map so the snapshot
// is safe to mutate / read concurrently with later writes (callers
// today call snapshot exactly once at the end of Stats(), so this is
// purely defensive). Returns nil when no entries were ever added so
// the cloud heartbeat's `omitempty` JSON tag drops the field cleanly.
func (c *compressionDayCap) snapshot() map[string]float64 {
	if c == nil || len(c.m) == 0 {
		return nil
	}
	out := c.m
	c.m = nil
	c.h = nil
	return out
}

// compressionDayHeap is a min-heap of day-key strings backing the cap
// container's eviction path. Day keys are fixed-width YYYY-MM-DD so
// lexical < is also chronological <; the heap min is therefore the
// oldest day in the cap.
//
// Implements container/heap.Interface. Kept private to the package so
// callers can't accidentally reach past the compressionDayCap façade.
type compressionDayHeap []string

func (h compressionDayHeap) Len() int           { return len(h) }
func (h compressionDayHeap) Less(i, j int) bool { return h[i] < h[j] }
func (h compressionDayHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

// Push / Pop are required by container/heap.Interface; callers should
// invoke heap.Push(&h, x) / heap.Pop(&h) rather than these directly.
func (h *compressionDayHeap) Push(x any) {
	*h = append(*h, x.(string))
}

func (h *compressionDayHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
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
	if !isAuditFile(base) {
		return time.Time{}, false
	}
	key := dayKeyFromName(base)
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
