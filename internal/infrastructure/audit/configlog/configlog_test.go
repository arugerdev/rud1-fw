package configlog

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
// verifies both files exist + the cross-file ordering is correct.
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

	for _, name := range []string{
		"audit-" + day1.Format("2006-01-02") + ".jsonl",
		"audit-" + day2.Format("2006-01-02") + ".jsonl",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected file %q: %v", name, err)
		}
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
	if err := l.PruneOld(); err != nil {
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
	if err := l.PruneOld(); err != nil {
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
	if err := l.PruneOld(); err != nil {
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
