package revlog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAppendAndListNewestFirst writes five entries and verifies List returns
// them in newest-first order with matching totals.
func TestAppendAndListNewestFirst(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir, 30)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	// Use a fixed base time so entries have deterministic unix seconds.
	base := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return base }

	for i := 0; i < 5; i++ {
		e := Entry{
			BusID:  "1-1",
			Reason: "policy",
			At:     base.Add(time.Duration(i) * time.Second).Unix(),
		}
		if err := l.Append(e); err != nil {
			t.Fatalf("Append[%d]: %v", i, err)
		}
	}

	items, total, err := l.List(ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 5 {
		t.Fatalf("total = %d, want 5", total)
	}
	if len(items) != 5 {
		t.Fatalf("len(items) = %d, want 5", len(items))
	}
	// Newest-first: At[0] > At[1] > ... > At[4]
	for i := 1; i < len(items); i++ {
		if items[i-1].At <= items[i].At {
			t.Fatalf("items not newest-first at %d: %d <= %d", i, items[i-1].At, items[i].At)
		}
	}
	if items[0].At != base.Add(4*time.Second).Unix() {
		t.Fatalf("newest At = %d, want %d", items[0].At, base.Add(4*time.Second).Unix())
	}
}

// TestRotationAcrossDates simulates a date rollover via the injected clock
// and verifies that both files are written, both are listed, and the result
// is ordered newest-first across the boundary.
func TestRotationAcrossDates(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir, 30)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	day1 := time.Date(2026, 4, 22, 23, 59, 0, 0, time.Local)
	day2 := time.Date(2026, 4, 23, 0, 1, 0, 0, time.Local)

	// First append lands on day1.
	l.now = func() time.Time { return day1 }
	if err := l.Append(Entry{BusID: "1-1", Reason: "policy", At: day1.Unix()}); err != nil {
		t.Fatalf("Append day1: %v", err)
	}
	// Bump the clock past midnight; ensureOpenLocked should rotate.
	l.now = func() time.Time { return day2 }
	if err := l.Append(Entry{BusID: "1-2", Reason: "unplugged", At: day2.Unix()}); err != nil {
		t.Fatalf("Append day2: %v", err)
	}

	// Both per-day files must exist on disk.
	for _, name := range []string{
		"revocations-" + day1.Format("2006-01-02") + ".jsonl",
		"revocations-" + day2.Format("2006-01-02") + ".jsonl",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected file %q: %v", name, err)
		}
	}

	items, total, err := l.List(ListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 2 {
		t.Fatalf("total = %d, want 2", total)
	}
	if items[0].BusID != "1-2" || items[1].BusID != "1-1" {
		t.Fatalf("items not newest-first across date boundary: %+v", items)
	}
}

// TestPruneOldKeepsNewest drops in three dated files and asserts PruneOld
// with maxFiles=2 deletes only the oldest.
func TestPruneOldKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir, 2)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	// Seed three files directly so we don't have to juggle the clock three
	// times through Append. The Logger doesn't care who wrote them, only
	// that they match the filenamePrefix pattern.
	days := []string{"2026-04-20", "2026-04-21", "2026-04-22"}
	for _, d := range days {
		p := filepath.Join(dir, "revocations-"+d+".jsonl")
		if err := os.WriteFile(p, []byte(`{"busId":"1-1","reason":"policy","at":0}`+"\n"), 0o644); err != nil {
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
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 2 {
		t.Fatalf("after prune got %d files, want 2: %v", len(names), names)
	}
	// The oldest (2026-04-20) must be gone.
	for _, n := range names {
		if n == "revocations-2026-04-20.jsonl" {
			t.Fatalf("oldest file was not pruned: %v", names)
		}
	}
}
