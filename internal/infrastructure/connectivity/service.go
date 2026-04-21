// service.go — composes the NM (WiFi+AP) and MM (cellular) backends into
// a single Service that the HTTP layer consumes.
//
// Preferred backend policy:
//   - Auto      → WiFi wins when connected, cellular as backup
//   - WiFi      → user explicitly pinned WiFi
//   - Cellular  → user explicitly pinned cellular (disables WiFi autoconnect)
package connectivity

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	cx "github.com/rud1-es/rud1-fw/internal/domain/connectivity"
)

// Service implements cx.Service using NM + MM.
type Service struct {
	nm *NMBackend
	mm *MMBackend

	mu        sync.RWMutex
	preferred cx.Preferred
	cellCfg   cx.CellularConfig

	apSSID string
	apPass string

	// internetProbe is swapped in tests; defaults to a TCP dial to 8.8.8.8:53.
	internetProbe func() bool
}

// Options configures Service.
type Options struct {
	NM        *NMBackend
	MM        *MMBackend
	APSSID    string
	APPass    string
	Preferred cx.Preferred
}

// New composes an NM + MM service.
func New(opts Options) *Service {
	if opts.Preferred == "" {
		opts.Preferred = cx.PreferredAuto
	}
	return &Service{
		nm:            opts.NM,
		mm:            opts.MM,
		apSSID:        opts.APSSID,
		apPass:        opts.APPass,
		preferred:     opts.Preferred,
		internetProbe: defaultInternetProbe,
	}
}

// Snapshot aggregates WiFi + cellular + AP + mode in a single round-trip.
func (s *Service) Snapshot(ctx context.Context) (*cx.Snapshot, error) {
	var wifi *cx.WiFiStatus
	if s.nm != nil {
		w, _ := s.nm.Status(ctx)
		wifi = w
	}
	var ap *cx.APStatus
	if s.nm != nil {
		a, _ := s.nm.APStatus(ctx)
		ap = a
	}
	var cell *cx.CellularStatus
	if s.mm != nil {
		c, err := s.mm.Status(ctx)
		if err != nil {
			log.Debug().Err(err).Msg("cellular status failed")
		}
		cell = c
	}

	mode := cx.ModeOffline
	switch {
	case ap != nil && ap.Active:
		mode = cx.ModeAP
	case wifi != nil && wifi.ConnectedSSID != "":
		mode = cx.ModeWiFi
	case cell != nil && cell.Connected:
		mode = cx.ModeCellular
	}

	s.mu.RLock()
	pref := s.preferred
	s.mu.RUnlock()

	return &cx.Snapshot{
		Mode:      mode,
		Preferred: pref,
		Internet:  s.internetProbe(),
		WiFi:      wifi,
		AP:        ap,
		Cellular:  cell,
		UpdatedAt: time.Now(),
	}, nil
}

func (s *Service) SetPreferred(_ context.Context, p cx.Preferred) error {
	switch p {
	case cx.PreferredAuto, cx.PreferredWiFi, cx.PreferredCellular:
	default:
		return fmt.Errorf("unknown preferred mode: %q", p)
	}
	s.mu.Lock()
	s.preferred = p
	s.mu.Unlock()
	return nil
}

// ── WiFi delegations ────────────────────────────────────────────────────────

func (s *Service) WiFiScan(ctx context.Context) ([]cx.WiFiNetwork, error) {
	if s.nm == nil {
		return nil, ErrUnavailable
	}
	return s.nm.Scan(ctx)
}
func (s *Service) WiFiSaved(ctx context.Context) ([]cx.SavedWiFi, error) {
	if s.nm == nil {
		return nil, ErrUnavailable
	}
	return s.nm.Saved(ctx)
}
func (s *Service) WiFiConnect(ctx context.Context, req cx.ConnectRequest) error {
	if s.nm == nil {
		return ErrUnavailable
	}
	err := s.nm.Connect(ctx, req)
	if err == nil {
		// On success we drop the setup AP (if any) — uplink is back.
		_ = s.nm.APDisable(ctx)
	}
	return err
}
func (s *Service) WiFiDisconnect(ctx context.Context) error {
	if s.nm == nil {
		return ErrUnavailable
	}
	return s.nm.Disconnect(ctx)
}
func (s *Service) WiFiForget(ctx context.Context, ssid string) error {
	if s.nm == nil {
		return ErrUnavailable
	}
	return s.nm.Forget(ctx, ssid)
}
func (s *Service) WiFiStatus(ctx context.Context) (*cx.WiFiStatus, error) {
	if s.nm == nil {
		return nil, ErrUnavailable
	}
	return s.nm.Status(ctx)
}

// ── Cellular delegations ────────────────────────────────────────────────────

func (s *Service) CellularStatus(ctx context.Context) (*cx.CellularStatus, error) {
	if s.mm == nil {
		return &cx.CellularStatus{Present: false, SIMState: cx.SIMUnknown}, nil
	}
	return s.mm.Status(ctx)
}

func (s *Service) CellularSetConfig(_ context.Context, cfg cx.CellularConfig) error {
	s.mu.Lock()
	s.cellCfg = cfg
	s.mu.Unlock()
	return nil
}

func (s *Service) CellularUnlockPIN(ctx context.Context, pin string) error {
	if s.mm == nil {
		return ErrUnavailable
	}
	return s.mm.UnlockPIN(ctx, pin)
}

func (s *Service) CellularConnect(ctx context.Context) error {
	if s.mm == nil {
		return ErrUnavailable
	}
	s.mu.RLock()
	cfg := s.cellCfg
	s.mu.RUnlock()
	return s.mm.Connect(ctx, cfg.APN, cfg.Username, cfg.Password)
}
func (s *Service) CellularDisconnect(ctx context.Context) error {
	if s.mm == nil {
		return ErrUnavailable
	}
	return s.mm.Disconnect(ctx)
}

// ── AP delegations ──────────────────────────────────────────────────────────

func (s *Service) APStatus(ctx context.Context) (*cx.APStatus, error) {
	if s.nm == nil {
		return &cx.APStatus{SSID: s.apSSID, Password: s.apPass}, nil
	}
	return s.nm.APStatus(ctx)
}
func (s *Service) APEnable(ctx context.Context) error {
	if s.nm == nil {
		return ErrUnavailable
	}
	return s.nm.APEnable(ctx)
}
func (s *Service) APDisable(ctx context.Context) error {
	if s.nm == nil {
		return ErrUnavailable
	}
	return s.nm.APDisable(ctx)
}

// ── Internet probe ──────────────────────────────────────────────────────────

func defaultInternetProbe() bool {
	return probeTCP("8.8.8.8:53", 2*time.Second) || probeTCP("1.1.1.1:53", 2*time.Second)
}
