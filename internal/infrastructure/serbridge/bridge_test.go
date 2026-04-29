package serbridge

import (
	"testing"
)

func TestPortAllocator(t *testing.T) {
	t.Run("allocates within range", func(t *testing.T) {
		a, err := NewPortAllocator(7700, 3)
		if err != nil {
			t.Fatalf("NewPortAllocator: %v", err)
		}
		got := []int{}
		for i := 0; i < 3; i++ {
			p, err := a.Allocate()
			if err != nil {
				t.Fatalf("Allocate: %v", err)
			}
			got = append(got, p)
		}
		want := []int{7700, 7701, 7702}
		for i, p := range got {
			if p != want[i] {
				t.Errorf("port[%d] = %d, want %d", i, p, want[i])
			}
		}
	})

	t.Run("ErrNoFreeSlots when full", func(t *testing.T) {
		a, _ := NewPortAllocator(7700, 2)
		_, _ = a.Allocate()
		_, _ = a.Allocate()
		if _, err := a.Allocate(); err != ErrNoFreeSlots {
			t.Errorf("expected ErrNoFreeSlots, got %v", err)
		}
	})

	t.Run("Release reuses ports LIFO", func(t *testing.T) {
		a, _ := NewPortAllocator(7700, 4)
		p1, _ := a.Allocate()
		p2, _ := a.Allocate()
		a.Release(p1)
		a.Release(p2)
		// LIFO: most recently released comes back first.
		got, _ := a.Allocate()
		if got != p2 {
			t.Errorf("Allocate after Release: got %d, want %d (LIFO)", got, p2)
		}
		got2, _ := a.Allocate()
		if got2 != p1 {
			t.Errorf("Allocate after Release (2nd): got %d, want %d", got2, p1)
		}
	})

	t.Run("Release of out-of-range port is no-op", func(t *testing.T) {
		a, _ := NewPortAllocator(7700, 2)
		_, _ = a.Allocate()
		a.Release(9999) // outside the range — must not panic
		if a.InUse() != 1 {
			t.Errorf("InUse=%d, want 1 (out-of-range release shouldn't change count)", a.InUse())
		}
	})

	t.Run("rejects invalid range", func(t *testing.T) {
		if _, err := NewPortAllocator(-1, 5); err == nil {
			t.Error("expected error for negative base, got nil")
		}
		if _, err := NewPortAllocator(7700, 0); err == nil {
			t.Error("expected error for zero max, got nil")
		}
		if _, err := NewPortAllocator(65530, 100); err == nil {
			t.Error("expected error when base+max overflows, got nil")
		}
	})
}

func TestFormatSerialSettings(t *testing.T) {
	cases := []struct {
		name     string
		baud     int
		dataBits int
		parity   string
		stopBits string
		want     string
	}{
		{"complete 8N1", 115200, 8, "N", "1", "115200 8N1"},
		{"baud only", 9600, 0, "", "", "9600"},
		{"frame only", 0, 8, "N", "1", "8N1"},
		{"empty", 0, 0, "", "", ""},
		{"7E2", 9600, 7, "E", "2", "9600 7E2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := FormatSerialSettings(c.baud, c.dataBits, c.parity, c.stopBits)
			if got != c.want {
				t.Errorf("FormatSerialSettings(%d, %d, %q, %q) = %q, want %q",
					c.baud, c.dataBits, c.parity, c.stopBits, got, c.want)
			}
		})
	}
}
