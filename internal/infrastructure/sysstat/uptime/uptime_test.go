package uptime

import (
	"os"
	"testing"
	"time"
)

func TestStore_AppendAndListNewestFirst(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStoreAt(dir)
	if err != nil {
		t.Fatalf("OpenStoreAt: %v", err)
	}
	base := time.Now().UTC().Truncate(time.Second)
	events := []Event{
		{At: base, Kind: "boot", Uptime: 0},
		{At: base.Add(time.Minute), Kind: "restart", Uptime: 60 * time.Second, Reason: "agent upgrade"},
		{At: base.Add(2 * time.Minute), Kind: "shutdown", Uptime: 120 * time.Second},
	}
	for i, ev := range events {
		if err := s.Append(ev); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	got := s.List(0)
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3", len(got))
	}
	// Newest-first ordering.
	if got[0].Kind != "shutdown" || got[1].Kind != "restart" || got[2].Kind != "boot" {
		t.Fatalf("unexpected order: %+v", got)
	}
	if got[1].Reason != "agent upgrade" {
		t.Fatalf("reason not preserved: %+v", got[1])
	}
	if got[1].Uptime != 60*time.Second {
		t.Fatalf("uptime not preserved: got %v", got[1].Uptime)
	}
}

func TestStore_CapEnforced(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStoreAt(dir)
	if err != nil {
		t.Fatalf("OpenStoreAt: %v", err)
	}
	base := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 205; i++ {
		ev := Event{
			At:     base.Add(time.Duration(i) * time.Second),
			Kind:   "boot",
			Uptime: time.Duration(i) * time.Second,
		}
		if err := s.Append(ev); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if got := s.Size(); got != maxEvents {
		t.Fatalf("size=%d, want %d", got, maxEvents)
	}
	all := s.List(0)
	if len(all) != maxEvents {
		t.Fatalf("List len=%d, want %d", len(all), maxEvents)
	}
	// Newest-first → first entry should be the very last appended (i=204).
	if all[0].Uptime != 204*time.Second {
		t.Fatalf("newest entry uptime=%v, want %v", all[0].Uptime, 204*time.Second)
	}
	// Oldest retained is i=5 (since the first 5 were dropped to make room).
	if all[len(all)-1].Uptime != 5*time.Second {
		t.Fatalf("oldest retained uptime=%v, want %v", all[len(all)-1].Uptime, 5*time.Second)
	}
}

func TestStore_ReloadAfterClose(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStoreAt(dir)
	if err != nil {
		t.Fatalf("OpenStoreAt: %v", err)
	}
	base := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 5; i++ {
		ev := Event{
			At:     base.Add(time.Duration(i) * time.Second),
			Kind:   "boot",
			Uptime: time.Duration(i) * time.Second,
			Reason: "n=" + itoa(i),
		}
		if err := s.Append(ev); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := OpenStoreAt(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := s2.Size(); got != 5 {
		t.Fatalf("after reopen size=%d, want 5", got)
	}
	all := s2.List(0)
	if len(all) != 5 {
		t.Fatalf("List len=%d, want 5", len(all))
	}
	// Newest-first: index 0 is i=4.
	if all[0].Reason != "n=4" || all[4].Reason != "n=0" {
		t.Fatalf("reasons not preserved across reload: %+v", all)
	}
}

func TestDetectBootEvent_SimulateHardwareReturnsFalse(t *testing.T) {
	// On Windows SimulateHardware() is always true; on Linux dev we force
	// it explicitly so the test is deterministic.
	prev := os.Getenv("RUD1_SIMULATE")
	t.Setenv("RUD1_SIMULATE", "1")
	t.Cleanup(func() {
		if prev == "" {
			_ = os.Unsetenv("RUD1_SIMULATE")
		} else {
			_ = os.Setenv("RUD1_SIMULATE", prev)
		}
	})

	ev, ok := DetectBootEvent("")
	if ok {
		t.Fatalf("expected (Event{}, false) under SimulateHardware, got %+v", ev)
	}
	if ev.Kind != "" || !ev.At.IsZero() {
		t.Fatalf("expected zero Event, got %+v", ev)
	}
}

// itoa avoids pulling strconv into the test for a single use; keeps the
// test file's import set minimal.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
