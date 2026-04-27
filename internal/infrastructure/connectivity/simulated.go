// Simulated connectivity backend — used on Windows and when the RUD1_SIMULATE
// flag is set on Linux. Lets us exercise the full panel flow without real
// radios and without requiring NetworkManager or ModemManager to be present.
package connectivity

import (
	"context"
	"sync"
	"time"

	cx "github.com/rud1-es/rud1-fw/internal/domain/connectivity"
)

// simulatedState holds mutable fake state (current SSID, AP on/off, etc.).
// Kept in-memory only — restarting the agent resets it.
type simulatedState struct {
	mu         sync.Mutex
	connected  string
	apActive   bool
	pinOK      bool
	cellConfig cx.CellularConfig
}

func newSimulated() *simulatedState {
	return &simulatedState{
		pinOK: true,
		cellConfig: cx.CellularConfig{
			Enabled:         false,
			APN:             "internet",
			RecommendedPlan: "IoT 1GB/mes (recomendado)",
		},
	}
}

func (s *simulatedState) Scan() []cx.WiFiNetwork {
	s.mu.Lock()
	defer s.mu.Unlock()
	return []cx.WiFiNetwork{
		{SSID: "MOVISTAR_ABCD", Security: cx.SecurityWPA2, SignalPct: 82, SignalDBm: -50, FrequencyM: 2437, Channel: 6, InUse: s.connected == "MOVISTAR_ABCD", Saved: true},
		{SSID: "OrangeHome-1234", Security: cx.SecurityWPA2, SignalPct: 65, SignalDBm: -60, FrequencyM: 5180, Channel: 36},
		{SSID: "Taller WiFi", Security: cx.SecurityWPA3, SignalPct: 48, SignalDBm: -70, FrequencyM: 2462, Channel: 11},
		{SSID: "Invitados", Security: cx.SecurityOpen, SignalPct: 32, SignalDBm: -78, FrequencyM: 2412, Channel: 1},
	}
}

func (s *simulatedState) Saved() []cx.SavedWiFi {
	return []cx.SavedWiFi{
		{SSID: "MOVISTAR_ABCD", Security: cx.SecurityWPA2, AutoConnect: true, Priority: 10, LastUsed: time.Now().Add(-2 * time.Hour)},
	}
}

func (s *simulatedState) Connect(req cx.ConnectRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connected = req.SSID
	return nil
}

func (s *simulatedState) Disconnect() { s.mu.Lock(); s.connected = ""; s.mu.Unlock() }

func (s *simulatedState) Status() *cx.WiFiStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &cx.WiFiStatus{Enabled: true, Interface: "wlan0"}
	if s.connected != "" {
		st.ConnectedSSID = s.connected
		st.IPv4 = "192.168.1.42"
		st.SignalPct = 82
		st.Frequency = 2437
	}
	return st
}

func (s *simulatedState) APEnable()  { s.mu.Lock(); s.apActive = true; s.mu.Unlock() }
func (s *simulatedState) APDisable() { s.mu.Lock(); s.apActive = false; s.mu.Unlock() }

func (s *simulatedState) APStatus(ssid, pass string) *cx.APStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &cx.APStatus{
		Active:    s.apActive,
		SSID:      ssid,
		Password:  pass,
		Interface: "wlan0",
		IPv4:      "192.168.50.1",
	}
}

func (s *simulatedState) Cellular() *cx.CellularStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &cx.CellularStatus{
		Present:      true,
		Model:        "Sierra Wireless MC7700 (simulated)",
		Manufacturer: "Sierra Wireless",
		Firmware:     "SWI9200M_03.05.23.02AP",
		IMEI:         "353456789012345",
		SIMState:     simSIMState(s.pinOK),
		Operator:     "Movistar",
		NetworkType:  "lte",
		SignalPct:    71,
		SignalDBm:    -62,
		Connected:    s.cellConfig.Enabled,
		IPv4:         simIP(s.cellConfig.Enabled),
		APN:          s.cellConfig.APN,
		Interface:    "wwan0",
		RxBytes:      uint64(12 << 20),
		TxBytes:      uint64(3 << 20),
		DataCapMB:    s.cellConfig.DataCapMB,
	}
}

func (s *simulatedState) UnlockPIN(pin string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pinOK = pin == "1234"
	if !s.pinOK {
		return errSimulatedBadPIN
	}
	return nil
}

func (s *simulatedState) SetCellConfig(cfg cx.CellularConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cellConfig = cfg
}

var errSimulatedBadPIN = &simError{"simulated: wrong PIN (try 1234)"}

type simError struct{ msg string }

func (e *simError) Error() string { return e.msg }

func simSIMState(ok bool) cx.SIMState {
	if ok {
		return cx.SIMUnlocked
	}
	return cx.SIMLocked
}
func simIP(on bool) string {
	if on {
		return "10.74.55.22"
	}
	return ""
}

// ── simulatedService satisfies cx.Service without any OS dependency. ───────

type simulatedService struct {
	state    *simulatedState
	apSSID   string
	apPass   string
	preferred cx.Preferred
	mu        sync.RWMutex
}

// NewSimulated returns a Service backed by in-memory fakes.
func NewSimulated(apSSID, apPass string) cx.Service {
	return &simulatedService{
		state:    newSimulated(),
		apSSID:   apSSID,
		apPass:   apPass,
		preferred: cx.PreferredAuto,
	}
}

func (s *simulatedService) Snapshot(ctx context.Context) (*cx.Snapshot, error) {
	wifi := s.state.Status()
	ap := s.state.APStatus(s.apSSID, s.apPass)
	cell := s.state.Cellular()
	mode := cx.ModeOffline
	switch {
	case ap.Active:
		mode = cx.ModeAP
	case wifi.ConnectedSSID != "":
		mode = cx.ModeWiFi
	case cell.Connected:
		mode = cx.ModeCellular
	}
	s.mu.RLock()
	pref := s.preferred
	s.mu.RUnlock()
	return &cx.Snapshot{
		Mode:      mode,
		Preferred: pref,
		Internet:  mode == cx.ModeWiFi || mode == cx.ModeCellular || mode == cx.ModeEthernet,
		WiFi:      wifi,
		Cellular:  cell,
		AP:        ap,
		UpdatedAt: time.Now(),
	}, nil
}

func (s *simulatedService) SetPreferred(_ context.Context, p cx.Preferred) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preferred = p
	return nil
}

func (s *simulatedService) WiFiScan(_ context.Context) ([]cx.WiFiNetwork, error) {
	return s.state.Scan(), nil
}
func (s *simulatedService) WiFiSaved(_ context.Context) ([]cx.SavedWiFi, error) {
	return s.state.Saved(), nil
}
func (s *simulatedService) WiFiConnect(_ context.Context, req cx.ConnectRequest) error {
	return s.state.Connect(req)
}
func (s *simulatedService) WiFiDisconnect(_ context.Context) error {
	s.state.Disconnect()
	return nil
}
func (s *simulatedService) WiFiForget(_ context.Context, _ string) error { return nil }
func (s *simulatedService) WiFiStatus(_ context.Context) (*cx.WiFiStatus, error) {
	return s.state.Status(), nil
}

func (s *simulatedService) CellularStatus(_ context.Context) (*cx.CellularStatus, error) {
	return s.state.Cellular(), nil
}
func (s *simulatedService) CellularSetConfig(_ context.Context, cfg cx.CellularConfig) error {
	s.state.SetCellConfig(cfg)
	return nil
}
func (s *simulatedService) CellularUnlockPIN(_ context.Context, pin string) error {
	return s.state.UnlockPIN(pin)
}
func (s *simulatedService) CellularConnect(_ context.Context) error {
	cfg := s.state.cellConfig
	cfg.Enabled = true
	s.state.SetCellConfig(cfg)
	return nil
}
func (s *simulatedService) CellularDisconnect(_ context.Context) error {
	cfg := s.state.cellConfig
	cfg.Enabled = false
	s.state.SetCellConfig(cfg)
	return nil
}

func (s *simulatedService) APStatus(_ context.Context) (*cx.APStatus, error) {
	return s.state.APStatus(s.apSSID, s.apPass), nil
}
func (s *simulatedService) APEnable(_ context.Context) error  { s.state.APEnable(); return nil }
func (s *simulatedService) APDisable(_ context.Context) error { s.state.APDisable(); return nil }

func (s *simulatedService) APSetCredentials(_ context.Context, ssid, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ssid != "" {
		s.apSSID = ssid
	}
	s.apPass = password
	return nil
}
