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
)

// SupervisorOptions tunes the auto-AP behaviour.
type SupervisorOptions struct {
	CheckInterval    time.Duration // default 15s
	OfflineToAP      time.Duration // default 90s
	OnlineToDropAP   time.Duration // default 30s
	BootGrace        time.Duration // default 60s (don't touch anything before this)
	AutoAPOnBoot     bool          // if true, skip the boot grace when already offline
}

// Supervisor watches the internet probe and toggles the AP.
type Supervisor struct {
	svc  *Service
	opts SupervisorOptions

	// test hook
	now func() time.Time

	mu            sync.Mutex
	offlineSince  time.Time
	onlineSince   time.Time
	apUp          bool
	started       time.Time
}

// NewSupervisor wires a supervisor around a Service. Pass a nil-safe Service;
// if s.nm is nil the supervisor will quietly no-op.
func NewSupervisor(s *Service, opts SupervisorOptions) *Supervisor {
	if opts.CheckInterval == 0 {
		opts.CheckInterval = 15 * time.Second
	}
	if opts.OfflineToAP == 0 {
		opts.OfflineToAP = 90 * time.Second
	}
	if opts.OnlineToDropAP == 0 {
		opts.OnlineToDropAP = 30 * time.Second
	}
	if opts.BootGrace == 0 {
		opts.BootGrace = 60 * time.Second
	}
	return &Supervisor{
		svc:     s,
		opts:    opts,
		now:     time.Now,
		started: time.Now(),
	}
}

// Run blocks until ctx is cancelled. Call it in its own goroutine.
func (s *Supervisor) Run(ctx context.Context) {
	if s.svc == nil || s.svc.nm == nil || !s.svc.nm.Available() {
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

	// Boot grace: don't touch anything in the first N seconds so DHCP has
	// a chance to lease before we panic and raise the AP.
	if !s.opts.AutoAPOnBoot && now.Sub(s.started) < s.opts.BootGrace {
		return
	}

	internet := s.svc.internetProbe()
	apStatus, _ := s.svc.nm.APStatus(ctx)
	s.apUp = apStatus != nil && apStatus.Active

	s.mu.Lock()
	defer s.mu.Unlock()

	if internet {
		if s.onlineSince.IsZero() {
			s.onlineSince = now
		}
		s.offlineSince = time.Time{}
		if s.apUp && now.Sub(s.onlineSince) >= s.opts.OnlineToDropAP {
			log.Info().Msg("uplink stable — dropping setup AP")
			if err := s.svc.nm.APDisable(ctx); err != nil {
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
		if err := s.svc.nm.APEnable(ctx); err != nil {
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
