package sysstat

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Disk-backed percentile history gives us a 24h rolling window that survives
// reboots. The in-memory RingBuffer only covers 1h (60 samples) so a Pi that
// reboots nightly would lose the full day's trend. A tiny JSONL file under
// /var/lib/rud1/percentiles/ solves that without adding a real DB dependency.
//
// Shape: one sample per line — `{"t":<unix-s>,"c":<cpu-pct>,"l":<loadavg1>}`.
// Field names are single-letter to keep the file small (~60 bytes/row, ~86KB
// for a full 24h buffer at 1/min cadence).
const (
	historyMaxSamples = 24 * 60 // 24h at 1 sample/minute
	historyFilename   = "percentiles-samples.jsonl"
	// trimThreshold is how many extra lines we tolerate in the file before
	// rewriting it. Rewrite is O(n) — we amortise by only doing it every
	// ~60 samples (1h of slack) instead of on every append.
	historyTrimThreshold = 60
)

// historyEntry is the on-disk row shape. Exported only via History() which
// converts to the public HistoryPoint.
type historyEntry struct {
	T int64   `json:"t"`
	C float64 `json:"c"`
	L float64 `json:"l"`
}

// HistoryPoint is one row of the rolling percentile history returned by
// Collector.History. Callers get a fully deserialised timestamp so they
// don't have to re-parse the on-disk epoch.
type HistoryPoint struct {
	At       time.Time `json:"at"`
	CPUPct   float64   `json:"cpuPct"`
	LoadAvg1 float64   `json:"loadAvg1"`
}

// HistoryStore is the disk-backed percentile-samples ring buffer. It is
// append-only with periodic rewrite; see Append for the retention contract.
type HistoryStore struct {
	mu      sync.Mutex
	dir     string
	path    string
	samples []historyEntry
	// appendsSinceTrim counts how many lines we've added to the file since
	// the last rewrite. Once it crosses historyTrimThreshold we rewrite the
	// file keeping only the last historyMaxSamples rows.
	appendsSinceTrim int
}

// NewHistoryStore opens (or creates) the samples file under dir. On first
// call it loads the existing rows into memory so Collector.History is warm
// immediately after a restart. A missing dir is created; a missing file is
// treated as empty history (not an error). If the dir can't be created the
// error is returned — the caller falls back to in-memory-only sampling.
func NewHistoryStore(dir string) (*HistoryStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("sysstat/history: mkdir %q: %w", dir, err)
	}
	h := &HistoryStore{
		dir:  dir,
		path: filepath.Join(dir, historyFilename),
	}
	if err := h.load(); err != nil {
		// A corrupt file shouldn't block boot — log and continue with empty
		// memory state. The next successful Append will overwrite via trim.
		log.Warn().Err(err).Str("path", h.path).Msg("sysstat/history: load failed, starting fresh")
		h.samples = nil
		h.appendsSinceTrim = historyTrimThreshold + 1 // force rewrite on next append
	}
	return h, nil
}

// load reads the on-disk JSONL into h.samples, keeping only the last
// historyMaxSamples rows if the file grew past the threshold (e.g. an older
// binary left a long trail before restart).
func (h *HistoryStore) load() error {
	f, err := os.Open(h.path)
	if err != nil {
		if os.IsNotExist(err) {
			h.samples = nil
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Rows are tiny — but keep the same 1 MiB safety net as revlog in case
	// someone points this at the wrong file.
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var out []historyEntry
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e historyEntry
		if err := json.Unmarshal(line, &e); err != nil {
			// Skip malformed lines rather than bailing — the file is self-
			// healing on the next trim.
			log.Debug().Err(err).Msg("sysstat/history: skipping malformed line")
			continue
		}
		out = append(out, e)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	// The file could be long if a previous process crashed before its trim
	// pass; clip to the tail.
	if len(out) > historyMaxSamples {
		out = out[len(out)-historyMaxSamples:]
	}
	// Keep the in-memory slice sorted by timestamp so History() can window
	// without re-sorting. The sampler always pushes monotonically; this
	// sort is a defensive no-op in the happy path.
	sort.Slice(out, func(i, j int) bool { return out[i].T < out[j].T })
	h.samples = out
	return nil
}

// Append writes one sample to disk and adds it to the in-memory slice.
// Every historyTrimThreshold appends the file is rewritten to contain at
// most historyMaxSamples rows (tail-keep), so the file size stays bounded
// on long-running agents.
func (h *HistoryStore) Append(at time.Time, cpuPct, loadAvg1 float64) error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	e := historyEntry{T: at.Unix(), C: cpuPct, L: loadAvg1}
	h.samples = append(h.samples, e)
	h.appendsSinceTrim++

	// Fast path: append one line. On periodic trim we rewrite the whole
	// file so the caller doesn't have to reason about tail offsets.
	if h.appendsSinceTrim >= historyTrimThreshold || len(h.samples) > historyMaxSamples+historyTrimThreshold {
		if err := h.rewriteLocked(); err != nil {
			return err
		}
		h.appendsSinceTrim = 0
		return nil
	}

	f, err := os.OpenFile(h.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("sysstat/history: open: %w", err)
	}
	defer f.Close()
	buf, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("sysstat/history: marshal: %w", err)
	}
	buf = append(buf, '\n')
	if _, err := f.Write(buf); err != nil {
		return fmt.Errorf("sysstat/history: write: %w", err)
	}
	// fsync is explicitly skipped on the hot path — we can afford to lose
	// the last few minutes of history after a power cut; the 1h in-memory
	// window is the authoritative source for the live /api/system/stats
	// response, so the disk file is strictly for post-reboot warm-up.
	return nil
}

// rewriteLocked serialises the tail of h.samples to a tmp file and renames
// it onto the real path atomically. Assumes h.mu is held.
func (h *HistoryStore) rewriteLocked() error {
	if len(h.samples) > historyMaxSamples {
		h.samples = h.samples[len(h.samples)-historyMaxSamples:]
	}
	tmp, err := os.CreateTemp(h.dir, historyFilename+".*")
	if err != nil {
		return fmt.Errorf("sysstat/history: tmp create: %w", err)
	}
	tmpPath := tmp.Name()
	writer := bufio.NewWriter(tmp)
	for _, e := range h.samples {
		buf, err := json.Marshal(e)
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
			return fmt.Errorf("sysstat/history: marshal: %w", err)
		}
		buf = append(buf, '\n')
		if _, err := writer.Write(buf); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
			return fmt.Errorf("sysstat/history: tmp write: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sysstat/history: tmp flush: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sysstat/history: tmp sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sysstat/history: tmp close: %w", err)
	}
	if err := os.Rename(tmpPath, h.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sysstat/history: rename: %w", err)
	}
	return nil
}

// History returns all samples captured within the last `window`. A zero
// or negative window returns everything the store has (up to ~24h). Order
// is oldest-first so a chart renderer can plot the points directly.
func (h *HistoryStore) History(window time.Duration) []HistoryPoint {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	cutoff := int64(0)
	if window > 0 {
		cutoff = time.Now().Unix() - int64(window.Seconds())
	}
	out := make([]HistoryPoint, 0, len(h.samples))
	for _, e := range h.samples {
		if e.T < cutoff {
			continue
		}
		out = append(out, HistoryPoint{
			At:       time.Unix(e.T, 0).UTC(),
			CPUPct:   e.C,
			LoadAvg1: e.L,
		})
	}
	return out
}

// Size returns the number of retained samples. Exposed for tests +
// diagnostic logging ("history: restored N samples on boot").
func (h *HistoryStore) Size() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.samples)
}
