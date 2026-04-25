// Connectivity supervisor — background loop that raises the setup hotspot
// automatically when the device has been without internet for too long,
// and drops it when uplink comes back. This is what lets a fresh device
// expose its own "Rud1-Setup-XXXX" SSID right after boot so an installer
// with a phone can configure WiFi or cellular.
//
// State machine is simple and hysteretic — we only change state once a
// threshold has been met continuously, to avoid flapping on flaky WiFi:
//
//     ┌──────────────┐  offline ≥ 90s   ┌──────────────┐
//     │  online      ├─────────────────▶│   ap-raised  │
//     │  ap-down     │                  │              │
//     └──────▲───────┘  online ≥ 30s    └──────┬───────┘
//            └───────────────────────── [uplink returned]
//
// The grace period after boot is longer (AutoAPBootGrace) so we don't flash
// the AP on a device that's still waiting for DHCP.
package connectivity

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	cx "github.com/rud1-es/rud1-fw/internal/domain/connectivity"
)

// apController is the slice of NMBackend the supervisor needs. Lifted to
// an interface so tests can drive the supervisor without an NMBackend
// (which requires nmcli on PATH).
type apController interface {
	Available() bool
	APStatus(ctx context.Context) (*cx.APStatus, error)
	APEnable(ctx context.Context) error
	APDisable(ctx context.Context) error
}

// SupervisorOptions tunes the auto-AP behaviour.
type SupervisorOptions struct {
	CheckInterval  time.Duration // default 15s
	OfflineToAP    time.Duration // default 15s — installer UX, NOT a long-lived flap margin
	OnlineToDropAP time.Duration // default 30s
	BootGrace      time.Duration // default 20s (don't touch anything before this)
	AutoAPOnBoot   bool          // if true, skip the boot grace when already offline

	// IsSetupComplete is consulted on every tick. When the function returns
	// false, the supervisor treats the device as in "first-boot wizard"
	// state: the AP is raised IMMEDIATELY and kept up regardless of
	// internet connectivity. When the function returns true, the normal
	// offline/online state machine applies. A nil getter is treated as
	// "always complete" (back-compat for legacy tests).
	IsSetupComplete func() bool
}

// Supervisor watches the internet probe and toggles the AP.
type Supervisor struct {
	svc  *Service
	opts SupervisorOptions

	// ap is the resolved AP controller — points at svc.nm in production
	// and at an in-memory fake in tests. Initialised by NewSupervisor.
	ap apController
	// internet returns true when uplink is reachable. Defaults to
	// svc.internetProbe; tests inject deterministic stubs.
	internet func() bool

	// test hook
	now func() time.Time

	mu           sync.Mutex
	offlineSince time.Time
	onlineSince  time.Time
	apUp         bool
	started      time.Time
}

// NewSupervisor wires a supervisor around a Service. Pass a nil-safe Service;
// if s.nm is nil the supervisor will quietly no-op.
func NewSupervisor(s *Service, opts SupervisorOptions) *Supervisor {
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
		// Conservative default: if the caller hasn't wired the wizard
		// state, assume the device is past the wizard. Existing unit
		// tests rely on this behaviour.
		opts.IsSetupComplete = func() bool { return true }
	}
	sup := &Supervisor{
		svc:     s,
		opts:    opts,
		now:     time.Now,
		started: time.Now(),
	}
	if s != nil {
		if s.nm != nil {
			sup.ap = s.nm
		}
		if s.internetProbe != nil {
			sup.internet = s.internetProbe
		}
	}
	return sup
}

// Run blocks until ctx is cancelled. Call it in its own goroutine.
func (s *Supervisor) Run(ctx context.Context) {
	if s.ap == nil || !s.ap.Available() {
		log.Info().Msg("connectivity supervisor disabled (NetworkManager not available)")
		return
	}

	log.Info().
		Dur("offline_to_ap", s.opts.OfflineToAP).
		Dur("online_to_drop_ap", s.opts.OnlineToDropAP).
		Msg("connectivity supervisor started")

	ticker := time.NewTicker(s.opts.CheckInterval)
	defer ticker.Stop()

	for {
		s.evaluate(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Supervisor) evaluate(ctx context.Context) {
	now := s.now()

	apStatus, _ := s.ap.APStatus(ctx)
	s.apUp = apStatus != nil && apStatus.Active

	// Pre-wizard: a device whose Setup.Complete=false has nothing
	// meaningful to do online (no API token agreed, nothing to phone
	// home about), so skip every grace/threshold and keep the AP up so
	// an installer can always reach it. Any "online" hysteresis would
	// just flicker the radio while the installer's phone is associated.
	if !s.opts.IsSetupComplete() {
		if !s.apUp {
			log.Info().Msg("setup not complete — raising setup AP unconditionally")
			if err := s.ap.APEnable(ctx); err != nil {
				log.Error().Err(err).Msg("supervisor: failed to raise AP (pre-wizard)")
			}
		}
		// Reset hysteresis state so the post-wizard transition starts fresh.
		s.mu.Lock()
		s.offlineSince = time.Time{}
		s.onlineSince = time.Time{}
		s.mu.Unlock()
		return
	}

	// Boot grace: don't touch anything in the first N seconds so DHCP has
	// a chance to lease before we panic and raise the AP.
	if !s.opts.AutoAPOnBoot && now.Sub(s.started) < s.opts.BootGrace {
		return
	}

	internet := false
	if s.internet != nil {
		internet = s.internet()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if internet {
		if s.onlineSince.IsZero() {
			s.onlineSince = now
		}
		s.offlineSince = time.Time{}
		if s.apUp && now.Sub(s.onlineSince) >= s.opts.OnlineToDropAP {
			log.Info().Msg("uplink stable — dropping setup AP")
			if err := s.ap.APDisable(ctx); err != nil {
				log.Warn().Err(err).Msg("supervisor: failed to drop AP")
			}
		}
		return
	}

	// Offline
	if s.offlineSince.IsZero() {
		s.offlineSince = now
	}
	s.onlineSince = time.Time{}
	if !s.apUp && now.Sub(s.offlineSince) >= s.opts.OfflineToAP {
		log.Warn().Dur("offline_for", now.Sub(s.offlineSince)).
			Msg("no uplink for threshold — raising setup AP")
		if err := s.ap.APEnable(ctx); err != nil {
			log.Error().Err(err).Msg("supervisor: failed to raise AP")
		}
	}
}

// ── internet probe primitive ────────────────────────────────────────────────

func probeTCP(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
