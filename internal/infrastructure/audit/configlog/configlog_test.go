package configlog

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// TestAppendAndListRoundTrip writes five entries and reads them back
// newest-first with the unpaginated total intact.
func TestAppendAndListRoundTrip(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	l, err := New(dir, Options{MaxFiles: 14, Now: func() time.Time { return base }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	for i := 0; i < 5; i++ {
		e := Entry{
			At:     base.Add(time.Duration(i) * time.Second).Unix(),
			Action: "system.timezone.set",
			Actor:  "operator",
			OK:     true,
		}
		if err := l.Append(context.Background(), e); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	items, err := l.List(ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 5 {
		t.Fatalf("len=%d, want 5", len(items))
	}
	for i := 1; i < len(items); i++ {
		if items[i-1].At <= items[i].At {
			t.Fatalf("not newest-first at %d: %d <= %d", i, items[i-1].At, items[i].At)
		}
	}
	if items[0].At != base.Add(4*time.Second).Unix() {
		t.Fatalf("newest At=%d", items[0].At)
	}

	// Total mirrors the unfiltered count.
	tot, err := l.Total(ListOptions{})
	if err != nil {
		t.Fatalf("Total: %v", err)
	}
	if tot != 5 {
		t.Fatalf("Total=%d, want 5", tot)
	}
}

// TestRotationAcrossDates simulates the clock crossing midnight and
// verifies the cross-file ordering is correct. Iter 41: the previous
// day's file is gzip-compressed in place, so we expect the archived
// `.jsonl.gz` for day1 and the active `.jsonl` for day2 — and the
// original day1 `.jsonl` must be gone.
func TestRotationAcrossDates(t *testing.T) {
	dir := t.TempDir()
	day1 := time.Date(2026, 4, 22, 23, 59, 0, 0, time.Local)
	day2 := time.Date(2026, 4, 23, 0, 1, 0, 0, time.Local)
	now := day1
	l, err := New(dir, Options{MaxFiles: 14, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	if err := l.Append(context.Background(), Entry{Action: "a", Actor: "operator", At: day1.Unix(), OK: true}); err != nil {
		t.Fatalf("Append day1: %v", err)
	}
	now = day2
	if err := l.Append(context.Background(), Entry{Action: "b", Actor: "operator", At: day2.Unix(), OK: true}); err != nil {
		t.Fatalf("Append day2: %v", err)
	}

	day1Plain := "audit-" + day1.Format("2006-01-02") + ".jsonl"
	day1Gz := day1Plain + ".gz"
	day2Plain := "audit-" + day2.Format("2006-01-02") + ".jsonl"

	if _, err := os.Stat(filepath.Join(dir, day1Gz)); err != nil {
		t.Fatalf("expected archived gz %q: %v", day1Gz, err)
	}
	if _, err := os.Stat(filepath.Join(dir, day1Plain)); !os.IsNotExist(err) {
		t.Fatalf("original .jsonl for day1 should have been removed; stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, day2Plain)); err != nil {
		t.Fatalf("expected active .jsonl for day2 %q: %v", day2Plain, err)
	}

	items, err := l.List(ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("len=%d, want 2", len(items))
	}
	if items[0].Action != "b" || items[1].Action != "a" {
		t.Fatalf("not newest-first across boundary: %+v", items)
	}
}

// TestPruneOldKeepsNewest seeds three dated files and asserts PruneOld
// with MaxFiles=2 deletes only the oldest.
func TestPruneOldKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir, Options{MaxFiles: 2})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	for _, d := range []string{"2026-04-20", "2026-04-21", "2026-04-22"} {
		p := filepath.Join(dir, "audit-"+d+".jsonl")
		if err := os.WriteFile(p, []byte(`{"at":0,"action":"x","actor":"operator","ok":true}`+"\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	if _, err := l.PruneOld(); err != nil {
		t.Fatalf("PruneOld: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("after prune got %d files, want 2", len(entries))
	}
	for _, e := range entries {
		if e.Name() == "audit-2026-04-20.jsonl" {
			t.Fatalf("oldest file not pruned")
		}
	}
}

// TestPruneRespectsCustomMaxFiles seeds twenty dated files and asserts
// the pruner honours a caller-supplied MaxFiles=7. This is the new
// path exercised by config.System.AuditRetentionDays — without it, an
// operator-set retention window would silently revert to the package
// default at the first rotation.
func TestPruneRespectsCustomMaxFiles(t *testing.T) {
	dir := t.TempDir()
	// 20 daily files, oldest first.
	dates := []string{
		"2026-04-01", "2026-04-02", "2026-04-03", "2026-04-04", "2026-04-05",
		"2026-04-06", "2026-04-07", "2026-04-08", "2026-04-09", "2026-04-10",
		"2026-04-11", "2026-04-12", "2026-04-13", "2026-04-14", "2026-04-15",
		"2026-04-16", "2026-04-17", "2026-04-18", "2026-04-19", "2026-04-20",
	}
	for _, d := range dates {
		p := filepath.Join(dir, "audit-"+d+".jsonl")
		if err := os.WriteFile(p, []byte(`{"at":0,"action":"x","actor":"operator","ok":true}`+"\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	l, err := New(dir, Options{MaxFiles: 7})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()
	if _, err := l.PruneOld(); err != nil {
		t.Fatalf("PruneOld: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 7 {
		t.Fatalf("after prune got %d files, want 7", len(entries))
	}
	// The 7 newest are 2026-04-14 .. 2026-04-20; nothing older may
	// survive.
	for _, e := range entries {
		if e.Name() < "audit-2026-04-14.jsonl" {
			t.Fatalf("retained file older than window: %s", e.Name())
		}
	}
}

// TestPruneDefaultMaxFilesIs14: Options{} (zero MaxFiles) must fall
// back to defaultMaxFiles=14, mirroring the documented contract that
// config.System.AuditRetentionDaysOrDefault relies on.
func TestPruneDefaultMaxFilesIs14(t *testing.T) {
	dir := t.TempDir()
	// 20 dated files; default retention should keep the newest 14.
	dates := []string{
		"2026-04-01", "2026-04-02", "2026-04-03", "2026-04-04", "2026-04-05",
		"2026-04-06", "2026-04-07", "2026-04-08", "2026-04-09", "2026-04-10",
		"2026-04-11", "2026-04-12", "2026-04-13", "2026-04-14", "2026-04-15",
		"2026-04-16", "2026-04-17", "2026-04-18", "2026-04-19", "2026-04-20",
	}
	for _, d := range dates {
		p := filepath.Join(dir, "audit-"+d+".jsonl")
		if err := os.WriteFile(p, []byte(`{"at":0,"action":"x","actor":"operator","ok":true}`+"\n"), 0o644); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	l, err := New(dir, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()
	if _, err := l.PruneOld(); err != nil {
		t.Fatalf("PruneOld: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != defaultMaxFiles {
		t.Fatalf("default-retention prune got %d files, want %d", len(entries), defaultMaxFiles)
	}
}

// TestSkipsMalformedLines: a corrupt line interleaved with valid ones
// must NOT cause List to error or drop the surrounding good records.
func TestSkipsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit-2026-04-23.jsonl")
	body := `{"at":1,"action":"a","actor":"operator","ok":true}` + "\n" +
		`not json` + "\n" +
		`{"at":2,"action":"b","actor":"operator","ok":true}` + "\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	l, err := New(dir, Options{MaxFiles: 14})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	items, err := l.List(ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("len=%d, want 2 (one corrupt line dropped)", len(items))
	}
}

// TestListFilters covers Action / Since / Until / Limit / Offset.
func TestListFilters(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	l, err := New(dir, Options{MaxFiles: 14, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	// Seed 6 entries spanning two actions and three timestamps.
	for i := 0; i < 6; i++ {
		action := "system.timezone.set"
		if i%2 == 1 {
			action = "system.ntpProbe.update"
		}
		e := Entry{
			At:     now.Add(time.Duration(i) * time.Minute).Unix(),
			Action: action,
			Actor:  "operator",
			OK:     true,
		}
		if err := l.Append(context.Background(), e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	// Action filter.
	got, err := l.List(ListOptions{Action: "system.timezone.set", Limit: 100})
	if err != nil {
		t.Fatalf("List action: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("action filter: len=%d, want 3", len(got))
	}
	for _, e := range got {
		if e.Action != "system.timezone.set" {
			t.Fatalf("leak: %s", e.Action)
		}
	}

	// Since/Until window: minute 2 .. minute 4 inclusive.
	since := now.Add(2 * time.Minute).Unix()
	until := now.Add(4 * time.Minute).Unix()
	got, err = l.List(ListOptions{Since: since, Until: until, Limit: 100})
	if err != nil {
		t.Fatalf("List window: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("since/until: len=%d, want 3", len(got))
	}

	// Limit=2 newest first.
	got, err = l.List(ListOptions{Limit: 2})
	if err != nil {
		t.Fatalf("List limit: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("limit: len=%d, want 2", len(got))
	}

	// Offset=2 with Limit=2 — skip first two.
	got, err = l.List(ListOptions{Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("List offset: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("offset: len=%d, want 2", len(got))
	}
}

// TestLoggerNoop: the no-op fallback satisfies the Logger interface and
// always returns empty slices / nil errors.
func TestLoggerNoop(t *testing.T) {
	var l Logger = LoggerNoop{}
	if err := l.Append(context.Background(), Entry{Action: "x"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := l.List(ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len=%d, want 0", len(got))
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestNewRejectsTraversal: a baseDir whose cleaned form contains ".."
// segments (i.e. an unanchored relative escape) must be refused at
// construction.
func TestNewRejectsTraversal(t *testing.T) {
	if _, err := New("../../etc", Options{}); err == nil {
		t.Fatalf("expected error for relative traversal baseDir")
	}
	if _, err := New("", Options{}); err == nil {
		t.Fatalf("expected error for empty baseDir")
	}
}

// TestRedactBlocksKnownKeys: documented sensitive keys are masked,
// everything else passes through. Case-insensitive.
func TestRedactBlocksKnownKeys(t *testing.T) {
	in := map[string]any{
		"deviceName": "Taller-A",
		"password":   "swordfish",
		"Token":      "abc123",
		"notes":      "hello",
	}
	out := Redact(in)
	if out["password"] != "[redacted]" {
		t.Fatalf("password not redacted: %v", out["password"])
	}
	if out["Token"] != "[redacted]" {
		t.Fatalf("Token not redacted: %v", out["Token"])
	}
	if out["deviceName"] != "Taller-A" {
		t.Fatalf("deviceName mangled: %v", out["deviceName"])
	}
	if out["notes"] != "hello" {
		t.Fatalf("notes mangled: %v", out["notes"])
	}
	if Redact(nil) != nil {
		t.Fatalf("nil should return nil")
	}
}

// TestSanitiseError clips long strings + strips newlines so JSONL
// integrity is preserved.
func TestSanitiseError(t *testing.T) {
	got := sanitiseError("first\nsecond")
	if strings.Contains(got, "\n") {
		t.Fatalf("newline leaked: %q", got)
	}
	long := strings.Repeat("x", errorMaxLen+50)
	got = sanitiseError(long)
	if len(got) > errorMaxLen {
		t.Fatalf("not clipped: len=%d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("missing ellipsis: %q", got[len(got)-10:])
	}
}

// TestStatsEmptyDir: a freshly-constructed logger with no entries
// reports zero counts and no boundary timestamps. lastPruneAt is set
// because New() runs an opportunistic prune pass on construction.
func TestStatsEmptyDir(t *testing.T) {
	dir := t.TempDir()
	fixed := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	l, err := New(dir, Options{MaxFiles: 14, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	got, err := l.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if got.TotalEntries != 0 {
		t.Fatalf("TotalEntries=%d, want 0", got.TotalEntries)
	}
	if got.TotalBytes != 0 {
		t.Fatalf("TotalBytes=%d, want 0", got.TotalBytes)
	}
	if got.FileCount != 0 {
		t.Fatalf("FileCount=%d, want 0", got.FileCount)
	}
	if !got.OldestEntryAt.IsZero() {
		t.Fatalf("OldestEntryAt should be zero, got %v", got.OldestEntryAt)
	}
	if !got.NewestEntryAt.IsZero() {
		t.Fatalf("NewestEntryAt should be zero, got %v", got.NewestEntryAt)
	}
	// New() runs prune on construction, so lastPruneAt is set.
	if got.LastPruneAt.IsZero() {
		t.Fatalf("LastPruneAt should be set after New(): got zero")
	}
	if !got.LastPruneAt.Equal(fixed) {
		t.Fatalf("LastPruneAt=%v, want %v", got.LastPruneAt, fixed)
	}
}

// TestStatsPopulatedDir: with entries spanning two days, counts/bytes
// are accumulated across files and oldest/newest reflect the first and
// last entry timestamps.
func TestStatsPopulatedDir(t *testing.T) {
	dir := t.TempDir()
	day1 := time.Date(2026, 4, 24, 10, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	now := day1
	l, err := New(dir, Options{MaxFiles: 14, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	for i := 0; i < 3; i++ {
		now = day1.Add(time.Duration(i) * time.Second)
		if err := l.Append(context.Background(), Entry{
			At: now.Unix(), Action: "x", Actor: "operator", OK: true,
		}); err != nil {
			t.Fatalf("Append day1: %v", err)
		}
	}
	for i := 0; i < 2; i++ {
		now = day2.Add(time.Duration(i) * time.Second)
		if err := l.Append(context.Background(), Entry{
			At: now.Unix(), Action: "y", Actor: "operator", OK: true,
		}); err != nil {
			t.Fatalf("Append day2: %v", err)
		}
	}

	got, err := l.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if got.TotalEntries != 5 {
		t.Fatalf("TotalEntries=%d, want 5", got.TotalEntries)
	}
	if got.FileCount != 2 {
		t.Fatalf("FileCount=%d, want 2", got.FileCount)
	}
	if got.TotalBytes <= 0 {
		t.Fatalf("TotalBytes=%d, want >0", got.TotalBytes)
	}
	wantNewest := day2.Add(time.Second).Unix()
	wantOldest := day1.Unix()
	if got.NewestEntryAt.Unix() != wantNewest {
		t.Fatalf("NewestEntryAt=%d, want %d", got.NewestEntryAt.Unix(), wantNewest)
	}
	if got.OldestEntryAt.Unix() != wantOldest {
		t.Fatalf("OldestEntryAt=%d, want %d", got.OldestEntryAt.Unix(), wantOldest)
	}
}

// TestStatsLastPruneAtAdvancesAfterPrune: a manual PruneOld() call
// updates lastPruneAt to the injected now()'s value.
func TestStatsLastPruneAtAdvancesAfterPrune(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 4, 25, 0, 0, 1, 0, time.UTC)
	now := t0
	l, err := New(dir, Options{MaxFiles: 14, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	// Sanity: New() set it to t0.
	first, _ := l.Stats()
	if !first.LastPruneAt.Equal(t0) {
		t.Fatalf("initial LastPruneAt=%v, want %v", first.LastPruneAt, t0)
	}

	// Advance the clock and re-prune.
	t1 := t0.Add(2 * time.Hour)
	now = t1
	if _, err := l.PruneOld(); err != nil {
		t.Fatalf("PruneOld: %v", err)
	}
	got, err := l.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if !got.LastPruneAt.Equal(t1) {
		t.Fatalf("LastPruneAt=%v, want %v", got.LastPruneAt, t1)
	}
}

// TestRotationProducesGzipArchive (iter 41): a date rotation closes
// the previous day's writer, gzips the file in place, and removes the
// original `.jsonl`. The .gz file must be a valid gzip stream that
// decodes back to the original JSONL bytes.
func TestRotationProducesGzipArchive(t *testing.T) {
	dir := t.TempDir()
	day1 := time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	now := day1
	l, err := New(dir, Options{MaxFiles: 14, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	if err := l.Append(context.Background(), Entry{
		At: day1.Unix(), Action: "a", Actor: "operator", OK: true,
	}); err != nil {
		t.Fatalf("Append day1: %v", err)
	}
	now = day2
	if err := l.Append(context.Background(), Entry{
		At: day2.Unix(), Action: "b", Actor: "operator", OK: true,
	}); err != nil {
		t.Fatalf("Append day2: %v", err)
	}

	day1Plain := filepath.Join(dir, "audit-2026-04-22.jsonl")
	day1Gz := day1Plain + ".gz"
	if _, err := os.Stat(day1Gz); err != nil {
		t.Fatalf("expected gzip archive at %s: %v", day1Gz, err)
	}
	if _, err := os.Stat(day1Plain); !os.IsNotExist(err) {
		t.Fatalf("original .jsonl should have been removed; got err=%v", err)
	}

	// Verify gzip stream decodes to the original JSONL line.
	f, err := os.Open(day1Gz)
	if err != nil {
		t.Fatalf("open gz: %v", err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gr.Close()
	buf := make([]byte, 1024)
	n, _ := gr.Read(buf)
	if !strings.Contains(string(buf[:n]), `"action":"a"`) {
		t.Fatalf("decoded gz content unexpected: %q", string(buf[:n]))
	}
}

// TestListReadsBothPlainAndGzip (iter 41): List must transparently
// consume entries from `.jsonl` AND `.jsonl.gz` files. Seed one of
// each (different days) and assert the merged newest-first ordering.
func TestListReadsBothPlainAndGzip(t *testing.T) {
	dir := t.TempDir()

	// Plain archive (pre-iter-41 style).
	plainPath := filepath.Join(dir, "audit-2026-04-22.jsonl")
	plainBody := `{"at":1745318400,"action":"plain","actor":"operator","ok":true}` + "\n"
	if err := os.WriteFile(plainPath, []byte(plainBody), 0o644); err != nil {
		t.Fatalf("write plain: %v", err)
	}

	// Gzipped archive (post-iter-41 style).
	gzPath := filepath.Join(dir, "audit-2026-04-23.jsonl.gz")
	gzBody := `{"at":1745404800,"action":"gz","actor":"operator","ok":true}` + "\n"
	gf, err := os.Create(gzPath)
	if err != nil {
		t.Fatalf("create gz: %v", err)
	}
	gw := gzip.NewWriter(gf)
	if _, err := gw.Write([]byte(gzBody)); err != nil {
		t.Fatalf("gz write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	if err := gf.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}

	l, err := New(dir, Options{MaxFiles: 14})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	items, err := l.List(ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("len=%d, want 2", len(items))
	}
	// Newest first: day 23 (gz) before day 22 (plain).
	if items[0].Action != "gz" || items[1].Action != "plain" {
		t.Fatalf("ordering wrong: %+v", items)
	}
}

// TestPruneOldDeletesGzipArchives (iter 41): when retention shrinks,
// PruneOld must remove `.jsonl.gz` files just like plain `.jsonl`.
// Seeded set mixes both variants to exercise the full path.
func TestPruneOldDeletesGzipArchives(t *testing.T) {
	dir := t.TempDir()

	// 4 day-files: 2 plain, 2 gz, oldest first.
	seedPlain := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("seed plain %s: %v", name, err)
		}
	}
	seedGz := func(name, body string) {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("create gz %s: %v", name, err)
		}
		gw := gzip.NewWriter(f)
		if _, err := gw.Write([]byte(body)); err != nil {
			t.Fatalf("write gz %s: %v", name, err)
		}
		if err := gw.Close(); err != nil {
			t.Fatalf("close gz %s: %v", name, err)
		}
		_ = f.Close()
	}

	seedPlain("audit-2026-04-20.jsonl", `{"at":1,"action":"oldest","actor":"operator","ok":true}`+"\n")
	seedGz("audit-2026-04-21.jsonl.gz", `{"at":2,"action":"old-gz","actor":"operator","ok":true}`+"\n")
	seedGz("audit-2026-04-22.jsonl.gz", `{"at":3,"action":"new-gz","actor":"operator","ok":true}`+"\n")
	seedPlain("audit-2026-04-23.jsonl", `{"at":4,"action":"newest","actor":"operator","ok":true}`+"\n")

	l, err := New(dir, Options{MaxFiles: 2})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	if _, err := l.PruneOld(); err != nil {
		t.Fatalf("PruneOld: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("post-prune file count=%d, want 2", len(entries))
	}
	want := map[string]bool{
		"audit-2026-04-22.jsonl.gz": true,
		"audit-2026-04-23.jsonl":    true,
	}
	for _, e := range entries {
		if !want[e.Name()] {
			t.Fatalf("unexpected surviving file: %s", e.Name())
		}
	}
}

// TestStatsTotalBytesReflectsCompressedSize (iter 41): a gzipped
// archive contributes its on-disk (compressed) size to TotalBytes,
// while EntryBytes still reflects the uncompressed JSONL footprint.
// We seed an artificially-compressible body so the ratio is provable.
func TestStatsTotalBytesReflectsCompressedSize(t *testing.T) {
	dir := t.TempDir()
	// 2 KiB of repetitive JSONL — compresses very well.
	var body strings.Builder
	for i := 0; i < 40; i++ {
		body.WriteString(`{"at":1745318400,"action":"compressible.repeat.action","actor":"operator","ok":true}` + "\n")
	}
	rawBytes := int64(body.Len())

	gzPath := filepath.Join(dir, "audit-2026-04-22.jsonl.gz")
	f, err := os.Create(gzPath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gw := gzip.NewWriter(f)
	if _, err := gw.Write([]byte(body.String())); err != nil {
		t.Fatalf("gz write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	_ = f.Close()

	l, err := New(dir, Options{MaxFiles: 14})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	got, err := l.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if got.FileCount != 1 {
		t.Fatalf("FileCount=%d, want 1", got.FileCount)
	}
	if got.TotalEntries != 40 {
		t.Fatalf("TotalEntries=%d, want 40", got.TotalEntries)
	}
	// On-disk size must be substantially smaller than the raw body
	// (gzip on this very repetitive input typically compresses 10x+).
	if got.TotalBytes >= rawBytes {
		t.Fatalf("TotalBytes=%d should be < raw=%d", got.TotalBytes, rawBytes)
	}
	// EntryBytes for gz archives is a re-marshal estimate — exact bytes
	// will differ from the seed because json.Marshal emits all
	// non-omitempty fields (e.g. `"previous":null,"next":null`) that
	// were absent in the hand-rolled seed line. We require only that
	// it's substantially larger than the on-disk gzip size (proving
	// it's not double-counting compressed bytes) and at least as big
	// as the raw seed (proving we counted every entry).
	if got.EntryBytes < rawBytes {
		t.Fatalf("EntryBytes=%d should be >= raw seed=%d", got.EntryBytes, rawBytes)
	}
	if got.EntryBytes <= got.TotalBytes {
		t.Fatalf("EntryBytes=%d should exceed compressed TotalBytes=%d", got.EntryBytes, got.TotalBytes)
	}
}

// TestStatsEntryBytesEqualsFileSizeForPlain (iter 41): for an
// uncompressed `.jsonl` file (the active day), EntryBytes equals the
// on-disk size byte-for-byte (no estimation involved).
func TestStatsEntryBytesEqualsFileSizeForPlain(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "audit-2026-04-23.jsonl")
	body := `{"at":1745404800,"action":"x","actor":"operator","ok":true}` + "\n" +
		`{"at":1745404801,"action":"y","actor":"operator","ok":true}` + "\n"
	if err := os.WriteFile(plainPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	l, err := New(dir, Options{MaxFiles: 14})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	got, err := l.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if got.EntryBytes != int64(len(body)) {
		t.Fatalf("EntryBytes=%d, want %d", got.EntryBytes, len(body))
	}
	if got.TotalBytes != int64(len(body)) {
		t.Fatalf("TotalBytes=%d, want %d (== plain on-disk)", got.TotalBytes, len(body))
	}
}

// TestRotationGzipFailureLeavesOriginal (iter 41): if the gzip step
// can't write its `.tmp` (we simulate this by creating the target as a
// directory the rename can't replace, or — simpler — by pre-creating a
// read-only `.tmp` file that O_CREATE|O_TRUNC can't replace), the
// rotation must still succeed and the original `.jsonl` must stay
// intact for the next rotation to retry.
//
// Skip on Windows: chmod-based read-only enforcement is unreliable
// (files remain truncatable by the owner). On Linux this is the right
// way to exercise the failure path.
func TestRotationGzipFailureLeavesOriginal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("read-only file enforcement differs on Windows; failure path covered manually")
	}
	dir := t.TempDir()
	day1 := time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	now := day1
	l, err := New(dir, Options{MaxFiles: 14, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	if err := l.Append(context.Background(), Entry{
		At: day1.Unix(), Action: "keepme", Actor: "operator", OK: true,
	}); err != nil {
		t.Fatalf("Append day1: %v", err)
	}

	// Pre-create the `.tmp` target as a directory: O_CREATE|O_WRONLY on
	// a directory path returns EISDIR, forcing compressArchivedFile's
	// "create tmp" branch to fail.
	day1GzTmp := filepath.Join(dir, "audit-2026-04-22.jsonl.gz.tmp")
	if err := os.Mkdir(day1GzTmp, 0o755); err != nil {
		t.Fatalf("mkdir blocker: %v", err)
	}

	now = day2
	if err := l.Append(context.Background(), Entry{
		At: day2.Unix(), Action: "newday", Actor: "operator", OK: true,
	}); err != nil {
		t.Fatalf("Append day2: %v", err)
	}

	// Rotation must have succeeded — day2 file exists.
	day2Plain := filepath.Join(dir, "audit-2026-04-23.jsonl")
	if _, err := os.Stat(day2Plain); err != nil {
		t.Fatalf("day2 active file missing: %v", err)
	}
	// Original day1 .jsonl must still be there (gzip failed, source
	// preserved for retry).
	day1Plain := filepath.Join(dir, "audit-2026-04-22.jsonl")
	if _, err := os.Stat(day1Plain); err != nil {
		t.Fatalf("original day1 .jsonl removed despite gzip failure: %v", err)
	}
	// And no `.gz` should exist (the rename never happened).
	day1Gz := day1Plain + ".gz"
	if _, err := os.Stat(day1Gz); !os.IsNotExist(err) {
		t.Fatalf("partial .gz appeared despite failure: err=%v", err)
	}

	// Verify both entries are still readable via List (one from the
	// original day1 plain file, one from day2 active file).
	items, err := l.List(ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("len=%d, want 2", len(items))
	}
}

// TestSameDayReopenDoesNotCompress (iter 41): if Append is called on
// the same day twice (no rotation), no gzip happens. Guards against an
// over-eager rotation path that would corrupt the still-active file.
func TestSameDayReopenDoesNotCompress(t *testing.T) {
	dir := t.TempDir()
	fixed := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	l, err := New(dir, Options{MaxFiles: 14, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	for i := 0; i < 3; i++ {
		if err := l.Append(context.Background(), Entry{
			At: fixed.Add(time.Duration(i) * time.Second).Unix(),
			Action: "x", Actor: "operator", OK: true,
		}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 file, got %d: %+v", len(entries), entries)
	}
	if !strings.HasSuffix(entries[0].Name(), ".jsonl") || strings.HasSuffix(entries[0].Name(), ".jsonl.gz") {
		t.Fatalf("active file should be plain .jsonl, got %s", entries[0].Name())
	}
}

// TestPruneOnShrinkHandlesGzipMix (iter 41): the iter-39 contract is
// "shrinking MaxFiles + calling PruneOld removes oldest files
// immediately"; that contract must keep working when archives are a
// mix of `.jsonl` and `.jsonl.gz`.
func TestPruneOnShrinkHandlesGzipMix(t *testing.T) {
	dir := t.TempDir()

	// 5 days — the 3 oldest gzipped, 2 newest plain.
	makeGz := func(name, body string) {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("create gz: %v", err)
		}
		gw := gzip.NewWriter(f)
		_, _ = gw.Write([]byte(body))
		_ = gw.Close()
		_ = f.Close()
	}
	makeGz("audit-2026-04-18.jsonl.gz", `{"at":1,"action":"a","actor":"operator","ok":true}`+"\n")
	makeGz("audit-2026-04-19.jsonl.gz", `{"at":2,"action":"b","actor":"operator","ok":true}`+"\n")
	makeGz("audit-2026-04-20.jsonl.gz", `{"at":3,"action":"c","actor":"operator","ok":true}`+"\n")
	if err := os.WriteFile(filepath.Join(dir, "audit-2026-04-21.jsonl"),
		[]byte(`{"at":4,"action":"d","actor":"operator","ok":true}`+"\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "audit-2026-04-22.jsonl"),
		[]byte(`{"at":5,"action":"e","actor":"operator","ok":true}`+"\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	l, err := New(dir, Options{MaxFiles: 5})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	// Sanity: List sees all 5.
	items, err := l.List(ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 5 {
		t.Fatalf("pre-shrink len=%d, want 5", len(items))
	}

	// Shrink to 3, prune.
	prev := l.SetMaxFiles(3)
	if prev != 5 {
		t.Fatalf("SetMaxFiles prev=%d, want 5", prev)
	}
	if _, err := l.PruneOld(); err != nil {
		t.Fatalf("PruneOld: %v", err)
	}
	left, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(left) != 3 {
		t.Fatalf("post-prune count=%d, want 3", len(left))
	}
	// The 3 newest survive; oldest two .gz removed.
	for _, e := range left {
		if e.Name() < "audit-2026-04-20" {
			t.Fatalf("survivor too old: %s", e.Name())
		}
	}
}

// TestAppendAutoFillsAt: an entry with At=0 gets stamped with now()'s
// unix time so callers don't have to remember.
func TestAppendAutoFillsAt(t *testing.T) {
	dir := t.TempDir()
	fixed := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	l, err := New(dir, Options{MaxFiles: 14, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	if err := l.Append(context.Background(), Entry{Action: "x", Actor: "operator", OK: true}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	items, err := l.List(ListOptions{Limit: 1})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 1 || items[0].At != fixed.Unix() {
		t.Fatalf("At not stamped: %+v", items)
	}
}

// captureGlobalLog redirects the global zerolog logger to an
// in-memory buffer for the duration of the test, restoring the
// previous logger via t.Cleanup. Returns the buffer; assertions
// inspect its contents after the call under test runs.
//
// We force the level to Debug so info-level emissions from the
// sweeper are always captured regardless of what the package
// default happens to be when the test binary starts.
func captureGlobalLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	prev := log.Logger
	prevLevel := zerolog.GlobalLevel()
	buf := &bytes.Buffer{}
	log.Logger = zerolog.New(buf).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() {
		log.Logger = prev
		zerolog.SetGlobalLevel(prevLevel)
	})
	return buf
}

// TestNewSweepsOrphanGzipTmp (iter 43): a `.gz.tmp` left behind by a
// prior process that crashed mid-rotation must be reaped on startup.
// The sweeper logs at info level with the path so an operator can see
// what was cleaned.
func TestNewSweepsOrphanGzipTmp(t *testing.T) {
	dir := t.TempDir()
	orphan := filepath.Join(dir, "audit-2026-04-20.jsonl.gz.tmp")
	if err := os.WriteFile(orphan, []byte("partial gzip stream"), 0o644); err != nil {
		t.Fatalf("write orphan: %v", err)
	}

	logBuf := captureGlobalLog(t)

	fixed := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	l, err := New(dir, Options{MaxFiles: 14, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan should have been removed; stat err=%v", err)
	}

	out := logBuf.String()
	if !strings.Contains(out, "reaped orphan .gz.tmp") {
		t.Fatalf("expected info log about reaped orphan, got: %s", out)
	}
	if !strings.Contains(out, "audit-2026-04-20.jsonl.gz.tmp") {
		t.Fatalf("expected log to mention orphan path, got: %s", out)
	}
}

// TestNewSilentWhenNoOrphan (iter 43): a clean baseDir at boot must
// produce no sweeper log spam — operators should not see noise on
// every restart of a healthy box.
func TestNewSilentWhenNoOrphan(t *testing.T) {
	dir := t.TempDir()

	logBuf := captureGlobalLog(t)

	fixed := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	l, err := New(dir, Options{MaxFiles: 14, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	out := logBuf.String()
	if strings.Contains(out, "reaped orphan") {
		t.Fatalf("did not expect orphan-reaped log on clean dir, got: %s", out)
	}
	if strings.Contains(out, "failed to remove orphan") {
		t.Fatalf("did not expect orphan-failed log on clean dir, got: %s", out)
	}
	if strings.Contains(out, "orphan .gz.tmp glob failed") {
		t.Fatalf("did not expect glob-failed log on clean dir, got: %s", out)
	}
}

// TestNewSweepsMultipleOrphans (iter 43): multiple crashed rotations
// can each leave an orphan; the sweeper must reap all of them in one
// pass, not just the first match. We also drop a non-matching file
// (a regular `.jsonl`) and a similarly-named decoy to confirm the
// glob is appropriately specific.
func TestNewSweepsMultipleOrphans(t *testing.T) {
	dir := t.TempDir()
	orphans := []string{
		"audit-2026-04-18.jsonl.gz.tmp",
		"audit-2026-04-19.jsonl.gz.tmp",
		"audit-2026-04-20.jsonl.gz.tmp",
	}
	for _, name := range orphans {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("partial"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// Decoys: must NOT be touched by the sweeper.
	keep := filepath.Join(dir, "audit-2026-04-22.jsonl")
	if err := os.WriteFile(keep, []byte(`{"at":1,"action":"x","actor":"o","ok":true}`+"\n"), 0o644); err != nil {
		t.Fatalf("write keep: %v", err)
	}
	keepGz := filepath.Join(dir, "audit-2026-04-21.jsonl.gz")
	if err := os.WriteFile(keepGz, []byte("not actually gzip but glob mustn't match"), 0o644); err != nil {
		t.Fatalf("write keepGz: %v", err)
	}

	fixed := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	l, err := New(dir, Options{MaxFiles: 14, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	for _, name := range orphans {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("orphan %s should have been removed; stat err=%v", name, err)
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("non-tmp .jsonl was wrongly removed: %v", err)
	}
	if _, err := os.Stat(keepGz); err != nil {
		t.Fatalf("non-tmp .jsonl.gz was wrongly removed: %v", err)
	}
}

// TestStatsCompressionByDayEmptyDir (iter 44): a freshly-constructed
// logger with no day-files reports a nil/empty CompressionByDay map.
// We accept either nil or zero-length so the contract is purely "no
// entries surfaced" — callers iterate with range either way.
func TestStatsCompressionByDayEmptyDir(t *testing.T) {
	dir := t.TempDir()
	fixed := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	l, err := New(dir, Options{MaxFiles: 14, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	got, err := l.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(got.CompressionByDay) != 0 {
		t.Fatalf("CompressionByDay=%v, want empty", got.CompressionByDay)
	}
}

// TestStatsCompressionByDaySingleGzip (iter 44): a single rotated
// `.jsonl.gz` archive must surface exactly one entry keyed by the day
// stamp parsed from the filename, with the ratio = entryBytes /
// totalBytes (entryBytes derived from the re-marshal estimate, so we
// assert "ratio is meaningfully > 1" rather than an exact value).
func TestStatsCompressionByDaySingleGzip(t *testing.T) {
	dir := t.TempDir()
	// Highly compressible body — same shape as the iter 41 test so
	// gzip squashes it down by an order of magnitude.
	var body strings.Builder
	for i := 0; i < 40; i++ {
		body.WriteString(`{"at":1745318400,"action":"compressible.repeat.action","actor":"operator","ok":true}` + "\n")
	}

	gzPath := filepath.Join(dir, "audit-2026-04-22.jsonl.gz")
	f, err := os.Create(gzPath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gw := gzip.NewWriter(f)
	if _, err := gw.Write([]byte(body.String())); err != nil {
		t.Fatalf("gz write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	_ = f.Close()

	l, err := New(dir, Options{MaxFiles: 14})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	got, err := l.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(got.CompressionByDay) != 1 {
		t.Fatalf("CompressionByDay len=%d, want 1: %v", len(got.CompressionByDay), got.CompressionByDay)
	}
	ratio, ok := got.CompressionByDay["2026-04-22"]
	if !ok {
		t.Fatalf("CompressionByDay missing 2026-04-22 key: %v", got.CompressionByDay)
	}
	// Repetitive JSONL of this shape compresses well past 2:1, so the
	// ratio must be substantially > 1. Belt-and-braces sanity bounds.
	if ratio <= 1.0 {
		t.Fatalf("ratio=%f, want >1.0 (real compression)", ratio)
	}
	if ratio > 1000 {
		t.Fatalf("ratio=%f, implausible (>1000x)", ratio)
	}
}

// TestStatsCompressionByDayMixedPlainAndGzip (iter 44): a directory
// holding both a plain `.jsonl` (the active day, ratio==1.0) and a
// `.jsonl.gz` archive surfaces only the gzip day. Ratio==1.0 carries
// no signal — emitting it would dilute the cloud's outlier histogram.
func TestStatsCompressionByDayMixedPlainAndGzip(t *testing.T) {
	dir := t.TempDir()

	// Plain active day — entryBytes == totalBytes, no compression.
	plainPath := filepath.Join(dir, "audit-2026-04-23.jsonl")
	plainBody := `{"at":1745404800,"action":"x","actor":"operator","ok":true}` + "\n"
	if err := os.WriteFile(plainPath, []byte(plainBody), 0o644); err != nil {
		t.Fatalf("write plain: %v", err)
	}

	// Compressible rotated day.
	var body strings.Builder
	for i := 0; i < 40; i++ {
		body.WriteString(`{"at":1745318400,"action":"compressible.repeat.action","actor":"operator","ok":true}` + "\n")
	}
	gzPath := filepath.Join(dir, "audit-2026-04-22.jsonl.gz")
	f, err := os.Create(gzPath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gw := gzip.NewWriter(f)
	if _, err := gw.Write([]byte(body.String())); err != nil {
		t.Fatalf("gz write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	_ = f.Close()

	l, err := New(dir, Options{MaxFiles: 14})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	got, err := l.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(got.CompressionByDay) != 1 {
		t.Fatalf("CompressionByDay len=%d, want 1 (plain day excluded): %v",
			len(got.CompressionByDay), got.CompressionByDay)
	}
	if _, ok := got.CompressionByDay["2026-04-22"]; !ok {
		t.Fatalf("missing gzip day: %v", got.CompressionByDay)
	}
	if _, ok := got.CompressionByDay["2026-04-23"]; ok {
		t.Fatalf("plain day must not appear: %v", got.CompressionByDay)
	}
	// Aggregate fields must remain unchanged in the mixed case — the
	// histogram is purely additive metadata.
	if got.FileCount != 2 {
		t.Fatalf("FileCount=%d, want 2", got.FileCount)
	}
}

// TestStatsCompressionByDayMalformedGzip (iter 44): a `.jsonl.gz` whose
// payload can't be decompressed (we write garbage bytes with the .gz
// suffix) must NOT contribute to the histogram. This mirrors the
// existing iter 41 EntryBytes drop behaviour — readJSONLFile fails,
// the file is skipped, and crucially CompressionByDay stays clean
// rather than emitting a nonsense ratio.
func TestStatsCompressionByDayMalformedGzip(t *testing.T) {
	dir := t.TempDir()

	bad := filepath.Join(dir, "audit-2026-04-20.jsonl.gz")
	if err := os.WriteFile(bad, []byte("this is not gzip data, not even close"), 0o644); err != nil {
		t.Fatalf("write bad: %v", err)
	}

	l, err := New(dir, Options{MaxFiles: 14})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	got, err := l.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(got.CompressionByDay) != 0 {
		t.Fatalf("CompressionByDay should be empty for malformed gzip, got %v", got.CompressionByDay)
	}
	// File still counts toward FileCount/TotalBytes — only the
	// uncompressed-derived fields drop out, same as EntryBytes.
	if got.FileCount != 1 {
		t.Fatalf("FileCount=%d, want 1 (malformed .gz still inventoried)", got.FileCount)
	}
}
