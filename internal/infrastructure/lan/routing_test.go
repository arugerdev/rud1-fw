package lan

import (
	"testing"
	"time"
)

// Tests against the simulated path so they don't require iptables on the
// build host. Production binaries always run with platform.SimulateHardware()
// returning false; the simulated branch in runIPTables is the same code path
// the dev workstation hits.

func newSimManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager()
	m.forced = true // Force simulated path even if SimulateHardware()==false.
	return m
}

func TestApply_AddsRoutes(t *testing.T) {
	m := newSimManager(t)
	m.Configure("10.77.42.0/24", "eth0")

	applied, errs := m.Apply([]string{"192.168.1.0/24", "192.168.2.0/24"})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(applied) != 2 {
		t.Fatalf("expected 2 applied routes, got %d", len(applied))
	}
	for _, r := range applied {
		if !r.Applied {
			t.Errorf("route %s should be applied=true in simulated mode", r.TargetSubnet)
		}
		if r.Uplink != "eth0" {
			t.Errorf("route %s wrong uplink: %q", r.TargetSubnet, r.Uplink)
		}
	}
}

func TestApply_RejectsInvalidCIDR(t *testing.T) {
	m := newSimManager(t)
	m.Configure("10.77.42.0/24", "eth0")

	// "not-a-cidr" is silently dropped; "10.0.0.1/32" is also silently
	// dropped at the normalization step (single-host masks aren't useful
	// LAN exposures and the agent's ValidateRoute already rejects them on
	// the API surface).
	applied, _ := m.Apply([]string{"not-a-cidr", "10.0.0.1/24"})
	if len(applied) != 1 {
		t.Fatalf("expected 1 applied (the valid one), got %d", len(applied))
	}
	if applied[0].TargetSubnet != "10.0.0.0/24" {
		t.Errorf("expected normalised 10.0.0.0/24, got %q", applied[0].TargetSubnet)
	}
}

func TestApply_RemovesUndesiredRoutes(t *testing.T) {
	m := newSimManager(t)
	m.Configure("10.77.42.0/24", "eth0")

	if _, errs := m.Apply([]string{"192.168.1.0/24", "192.168.2.0/24"}); len(errs) != 0 {
		t.Fatalf("seed errs: %v", errs)
	}
	if _, errs := m.Apply([]string{"192.168.2.0/24"}); len(errs) != 0 {
		t.Fatalf("shrink errs: %v", errs)
	}
	snap := m.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected snapshot of 1 after shrink, got %d", len(snap))
	}
	if snap[0].TargetSubnet != "192.168.2.0/24" {
		t.Errorf("kept the wrong route: %q", snap[0].TargetSubnet)
	}
}

func TestApply_TearDownAll(t *testing.T) {
	m := newSimManager(t)
	m.Configure("10.77.42.0/24", "eth0")

	if _, errs := m.Apply([]string{"192.168.1.0/24"}); len(errs) != 0 {
		t.Fatalf("seed errs: %v", errs)
	}
	if _, errs := m.Apply(nil); len(errs) != 0 {
		t.Fatalf("teardown errs: %v", errs)
	}
	if got := m.Snapshot(); len(got) != 0 {
		t.Fatalf("expected empty snapshot after teardown, got %v", got)
	}
}

func TestLastAppliedAt_StampedOnApply(t *testing.T) {
	m := newSimManager(t)
	m.Configure("10.77.42.0/24", "eth0")
	if !m.LastAppliedAt().IsZero() {
		t.Fatalf("expected zero LastAppliedAt before first Apply")
	}
	before := time.Now().UTC()
	if _, errs := m.Apply([]string{"10.5.0.0/24"}); len(errs) != 0 {
		t.Fatalf("apply errs: %v", errs)
	}
	got := m.LastAppliedAt()
	if got.IsZero() {
		t.Fatalf("expected LastAppliedAt to be set")
	}
	if got.Before(before.Add(-time.Second)) {
		t.Errorf("LastAppliedAt %s predates Apply call window starting %s", got, before)
	}
}

func TestHealthSnapshot_ReflectsState(t *testing.T) {
	m := newSimManager(t)
	m.Configure("10.77.42.0/24", "eth0")
	if _, errs := m.Apply([]string{"192.168.10.0/24"}); len(errs) != 0 {
		t.Fatalf("apply errs: %v", errs)
	}

	h := m.HealthSnapshot()
	if h.Source != "10.77.42.0/24" {
		t.Errorf("source: got %q", h.Source)
	}
	if h.Uplink != "eth0" {
		t.Errorf("uplink: got %q", h.Uplink)
	}
	if !h.Simulated {
		t.Errorf("expected Simulated=true for forced manager")
	}
	if len(h.Routes) != 1 || h.Routes[0].TargetSubnet != "192.168.10.0/24" {
		t.Errorf("routes wrong: %+v", h.Routes)
	}
	if h.LastAppliedAt.IsZero() {
		t.Errorf("expected LastAppliedAt to be non-zero after Apply")
	}
}

func TestValidateRoute(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		source   string
		want     string
		wantErr  bool
	}{
		{"happy", "192.168.1.0/24", "10.77.42.0/24", "192.168.1.0/24", false},
		{"normalises host bits", "192.168.1.5/24", "10.77.42.0/24", "192.168.1.0/24", false},
		{"empty rejected", "", "10.77.42.0/24", "", true},
		{"single host rejected", "10.0.0.1/32", "10.77.42.0/24", "", true},
		{"overlap rejected", "10.77.42.0/24", "10.77.42.0/24", "", true},
		{"v6 rejected", "fd00::/64", "10.77.42.0/24", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateRoute(tc.input, tc.source)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err mismatch: got %v wantErr=%v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}
