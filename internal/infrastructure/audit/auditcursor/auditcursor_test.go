package auditcursor

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoad_MissingFile_ReturnsZeroFalseNoError: first-boot path. The
// agent uses the !exists signal to default the cursor to time.Now()
// instead of zero so it doesn't spam-ship history.
func TestLoad_MissingFile_ReturnsZeroFalseNoError(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, exists, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if exists {
		t.Fatalf("expected exists=false on missing file")
	}
	if !got.IsZero() {
		t.Fatalf("expected zero time on missing file, got %v", got)
	}
}

// TestCommitThenLoad_RoundTrip persists a timestamp and reads it back.
// We compare via Equal because the on-disk form is RFC3339 (second
// precision) and the input may carry sub-second fractions.
func TestCommitThenLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	want := time.Date(2026, 4, 25, 12, 34, 56, 0, time.UTC)
	if err := s.Commit(want); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Re-open via a new store so we read from disk, not from the cache.
	s2, err := New(dir)
	if err != nil {
		t.Fatalf("re-New: %v", err)
	}
	got, exists, err := s2.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !exists {
		t.Fatalf("expected exists=true after Commit")
	}
	if !got.Equal(want) {
		t.Fatalf("round-trip mismatch: want %v got %v", want, got)
	}
}

// TestCommit_AtomicTmpRename verifies that after a successful Commit no
// .tmp sidecar lingers in the data dir. The atomic rename is what
// protects us against a torn write on power loss.
func TestCommit_AtomicTmpRename(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Commit(time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("stale .tmp sidecar left behind: %s", e.Name())
		}
	}
}

// TestLoad_MalformedFile_Errors: a corrupt JSON file must surface as an
// error so the operator notices, not be silently ignored as "missing".
func TestLoad_MalformedFile_Errors(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("not json"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, err := s.Load(); err == nil {
		t.Fatalf("expected error on malformed cursor file")
	}
}

// TestLoad_WrongVersion_Errors: a bumped on-disk version must error
// rather than be silently rewritten with a stale value.
func TestLoad_WrongVersion_Errors(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bad := []byte(`{"version":99,"lastShippedAt":"2026-04-25T12:00:00Z"}`)
	if err := os.WriteFile(filepath.Join(dir, FileName), bad, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, err := s.Load(); err == nil {
		t.Fatalf("expected error on wrong-version cursor file")
	}
}

// TestNew_EmptyDir_Errors: defensive — we must not silently fall back
// to CWD when the caller forgot to populate platform.DataDir().
func TestNew_EmptyDir_Errors(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatalf("expected error on empty dir")
	}
}
