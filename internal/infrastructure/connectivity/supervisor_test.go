package connectivity

import (
	"context"
	"sync"
	"testing"
	"time"

	cx "github.com/rud1-es/rud1-fw/internal/domain/connectivity"
)

// fakeAP is a minimal apController stub. Driven by the test: APEnable/Disable
// flip an in-memory flag that APStatus reflects, and call counters let the
// test assert exact invocation patterns.
type fakeAP struct {
	mu             sync.Mutex
	available      bool
	active         bool
	enableCalls    int
	disableCalls   int
	enableShouldErr error
}

func (f *fakeAP) Available() bool { return f.available }
func (f *fakeAP) APStatus(_ context.Context) (*cx.APStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &cx.APStatus{Active: f.active}, nil
}
func (f *fakeAP) APEnable(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enableCalls++
	if f.enableShouldErr != nil {
		return f.enableShouldErr
	}
	f.active = true
	return nil
}
func (f *fakeAP) APDisable(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disableCalls++
	f.active = false
	return nil
}

// newSupForTest constructs a Supervisor bypassing NewSupervisor's NM
// requirement so we can drive the apController and clock directly.
func newSupForTest(ap apController, internet func() bool, opts SupervisorOptions, now time.Time) *Supervisor {
	if opts.CheckInterval == 0 {
		opts.CheckInterval = 15 * time.Second
	}
	if opts.OfflineToAP == 0 {
		opts.OfflineToAP = 15 * time.Second
	}
	if opts.OnlineToDropAP == 0 {
		opts.OnlineToDropAP = 30 * time.Second
	}
	if opts.BootGrace == 0 {
		opts.BootGrace = 20 * time.Second
	}
	if opts.IsSetupComplete == nil {
		opts.IsSetupComplete = func() bool { return true }
	}
	current := now
	return &Supervisor{
		opts:     opts,
		ap:       ap,
		internet: internet,
		now:      func() time.Time { return current },
		started:  current,
	}
}

// TestSupervisor_PreWizardOfflineRaisesAP: with IsSetupComplete()=false +
// uplink down, the supervisor should raise the AP on the very first tick
// (no boot grace, no offline threshold) so a freshly-flashed device
// without WiFi/Ethernet still exposes a way for the installer to reach
// it. After flipping IsSetupComplete()=true the AP must drop within
// OnlineToDropAP once uplink stabilises.
func TestSupervisor_PreWizardOfflineRaisesAP(t *testing.T) {
	ap := &fakeAP{available: true}

	complete := false
	getter := func() bool { return complete }
	online := false

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sup := newSupForTest(ap, func() bool { return online }, SupervisorOptions{
		IsSetupComplete: getter,
		OfflineToAP:     15 * time.Second,
		OnlineToDropAP:  30 * time.Second,
		BootGrace:       20 * time.Second,
	}, now)

	// Tick 1: complete=false, no uplink → AP raised IMMEDIATELY despite
	// still being inside boot grace.
	sup.evaluate(context.Background())
	if ap.enableCalls != 1 {
		t.Fatalf("APEnable calls = %d after first tick (want 1)", ap.enableCalls)
	}
	if !ap.active {
		t.Fatalf("AP must be active after first tick when setup not complete + offline")
	}

	// Tick 2 (still pre-wizard, AP already up): no further enable calls.
	sup.evaluate(context.Background())
	if ap.enableCalls != 1 {
		t.Fatalf("APEnable should be idempotent while already up; got %d calls", ap.enableCalls)
	}

	// Flip wizard complete + uplink up. Advance clock past
	// OnlineToDropAP so the supervisor decides to drop.
	complete = true
	online = true
	current := now
	advance := func(d time.Duration) {
		current = current.Add(d)
		sup.now = func() time.Time { return current }
	}
	// Tick 3 — wizard complete, online for 0s; AP still up but online
	// timer just started. Boot grace has already passed (20s elapsed).
	advance(21 * time.Second)
	sup.evaluate(context.Background())
	if !ap.active {
		t.Fatalf("AP should still be up — only %s online so far", "0s")
	}

	// Tick 4 — clock has now been online > OnlineToDropAP. AP must drop.
	advance(31 * time.Second)
	sup.evaluate(context.Background())
	if ap.active {
		t.Fatalf("AP should have dropped after %s online (>= OnlineToDropAP)", "31s")
	}
	if ap.disableCalls == 0 {
		t.Fatalf("APDisable was never called after wizard complete + online")
	}
}

// TestSupervisor_PreWizardOnlineSkipsAP: with IsSetupComplete()=false but
// uplink already up (Ethernet plugged in, or WiFi pre-configured on the
// SD card before first boot), the supervisor MUST NOT raise the setup
// AP. Otherwise we thrash the same wlan0 that's serving the LAN, break
// mDNS, and lock the installer out of the panel they could already
// reach via http://<host>.local.
func TestSupervisor_PreWizardOnlineSkipsAP(t *testing.T) {
	ap := &fakeAP{available: true}

	complete := false
	online := true

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sup := newSupForTest(ap, func() bool { return online }, SupervisorOptions{
		IsSetupComplete: func() bool { return complete },
	}, now)

	// Repeated ticks while pre-wizard + online: no enable, no disable.
	for i := 0; i < 5; i++ {
		sup.evaluate(context.Background())
	}
	if ap.enableCalls != 0 {
		t.Fatalf("AP must not be raised pre-wizard when uplink present; got %d enable calls", ap.enableCalls)
	}
	if ap.disableCalls != 0 {
		t.Fatalf("AP must not be touched at all when never raised; got %d disable calls", ap.disableCalls)
	}
}

// TestSupervisor_PreWizardOnlineDropsExistingAP: edge case — the AP was
// up (e.g. raised earlier when offline) and uplink came back during the
// wizard. The supervisor should drop the AP immediately so the LAN
// stops being thrashed; the wizard can be finished from the panel.
func TestSupervisor_PreWizardOnlineDropsExistingAP(t *testing.T) {
	ap := &fakeAP{available: true, active: true}

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sup := newSupForTest(ap, func() bool { return true /* online */ }, SupervisorOptions{
		IsSetupComplete: func() bool { return false /* pre-wizard */ },
	}, now)

	sup.evaluate(context.Background())
	if ap.active {
		t.Fatalf("AP must be dropped pre-wizard once uplink is present")
	}
	if ap.disableCalls != 1 {
		t.Fatalf("APDisable should have been called once; got %d", ap.disableCalls)
	}
}

// TestSupervisor_PostWizardOfflineRaisesAfterThreshold validates that the
// existing offline→AP behaviour still works once the wizard is complete.
// Boot grace must elapse first, then OfflineToAP, before the AP is raised.
func TestSupervisor_PostWizardOfflineRaisesAfterThreshold(t *testing.T) {
	ap := &fakeAP{available: true}
	internetVal := false

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sup := newSupForTest(ap, func() bool { return internetVal }, SupervisorOptions{
		IsSetupComplete: func() bool { return true },
		OfflineToAP:     15 * time.Second,
		OnlineToDropAP:  30 * time.Second,
		BootGrace:       20 * time.Second,
	}, now)

	current := now
	advance := func(d time.Duration) {
		current = current.Add(d)
		sup.now = func() time.Time { return current }
	}

	// Tick within boot grace (5s in): nothing happens.
	advance(5 * time.Second)
	sup.evaluate(context.Background())
	if ap.enableCalls != 0 {
		t.Fatalf("AP must not raise during boot grace; got %d enable calls", ap.enableCalls)
	}

	// Cross boot grace + start offline timer (now 25s in).
	advance(20 * time.Second)
	sup.evaluate(context.Background())
	if ap.enableCalls != 0 {
		t.Fatalf("AP must not raise on first offline observation; got %d", ap.enableCalls)
	}

	// Cross OfflineToAP threshold (now 41s in, offline for 16s).
	advance(16 * time.Second)
	sup.evaluate(context.Background())
	if ap.enableCalls != 1 {
		t.Fatalf("AP should be raised after %s offline; got %d enable calls", "16s", ap.enableCalls)
	}
}
