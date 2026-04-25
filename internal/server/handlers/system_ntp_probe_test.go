package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/rud1-es/rud1-fw/internal/config"
)

// loadConfigForTest writes a minimal YAML to a temp dir and loads it.
// Returns a config whose Path is set, so Save() can round-trip.
func loadConfigForTest(t *testing.T, body string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}

// minimalConfigYAML returns a barely-valid agent config for tests that
// only care about cfg.System round-tripping. Defaults filled by
// config.Load are sufficient for the rest.
func minimalConfigYAML() string {
	return `
log_level: info
server:
  host: "127.0.0.1"
  port: 8080
  auth_token: "test"
cloud:
  base_url: "https://example.test"
vpn:
  interface: "wg0"
  config_path: "/tmp/wg0.conf"
usb:
  bind_port: 3240
network:
  wifi_interface: "wlan0"
  ap_interface: "wlan0"
  ap_cidr: "192.168.50.1/24"
setup:
  complete: false
system:
  external_ntp_probe_enabled: false
  external_ntp_probe_timeout: 2s
`
}

func newNTPProbeRouter(t *testing.T) (*chi.Mux, *config.Config, *SystemTimeHealthHandler) {
	t.Helper()
	cfg := loadConfigForTest(t, minimalConfigYAML())
	timeH := NewSystemTimeHealthHandlerWithProbe(ExternalNTPProbeOptions{
		Enabled:   cfg.System.ExternalNTPProbeEnabled,
		Servers:   cfg.System.ExternalNTPServers,
		PerServer: cfg.System.ExternalNTPProbeTimeout,
	})
	h := NewSystemNTPProbeConfigHandler(cfg, timeH)
	r := chi.NewRouter()
	r.Get("/api/system/ntp-probe-config", h.Get)
	r.Put("/api/system/ntp-probe-config", h.Set)
	return r, cfg, timeH
}

// TestNTPProbeConfig_GetReturnsDefaults: with the minimal YAML,
// the handler reports disabled / empty / 2s timeout.
func TestNTPProbeConfig_GetReturnsDefaults(t *testing.T) {
	r, _, _ := newNTPProbeRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/system/ntp-probe-config", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got ntpProbeConfigResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Enabled {
		t.Fatalf("enabled=%v, want false", got.Enabled)
	}
	if len(got.Servers) != 0 {
		t.Fatalf("servers=%v, want empty", got.Servers)
	}
	if got.TimeoutSeconds != 2 {
		t.Fatalf("timeoutSeconds=%d, want 2", got.TimeoutSeconds)
	}
}

// TestNTPProbeConfig_PutFullUpdate: a complete payload toggles all three
// dimensions, persists to disk, and pushes the new options into the
// time-health handler.
func TestNTPProbeConfig_PutFullUpdate(t *testing.T) {
	r, cfg, timeH := newNTPProbeRouter(t)

	body := `{"enabled":true,"servers":["pool.ntp.org","time.cloudflare.com"],"timeoutSeconds":3}`
	req := httptest.NewRequest(http.MethodPut, "/api/system/ntp-probe-config", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got ntpProbeConfigResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Enabled {
		t.Fatalf("enabled=%v, want true", got.Enabled)
	}
	if len(got.Servers) != 2 || got.Servers[0] != "pool.ntp.org" || got.Servers[1] != "time.cloudflare.com" {
		t.Fatalf("servers=%v, want [pool.ntp.org time.cloudflare.com]", got.Servers)
	}
	if got.TimeoutSeconds != 3 {
		t.Fatalf("timeoutSeconds=%d, want 3", got.TimeoutSeconds)
	}

	// Live time-health handler picks up the change.
	live := timeH.ProbeOptions()
	if !live.Enabled || len(live.Servers) != 2 || live.PerServer != 3*time.Second {
		t.Fatalf("live opts not propagated: %+v", live)
	}

	// Cfg in memory was mutated.
	if !cfg.System.ExternalNTPProbeEnabled {
		t.Fatalf("cfg.System.ExternalNTPProbeEnabled not set")
	}

	// Disk reload sees the persisted state.
	reloaded, err := config.Load(cfg.Path)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if !reloaded.System.ExternalNTPProbeEnabled || len(reloaded.System.ExternalNTPServers) != 2 ||
		reloaded.System.ExternalNTPProbeTimeout != 3*time.Second {
		t.Fatalf("reloaded config differs: %+v", reloaded.System)
	}
}

// TestNTPProbeConfig_PutPartialPreservesOthers: a partial payload (only
// `enabled`) must NOT clear `servers` or `timeoutSeconds`.
func TestNTPProbeConfig_PutPartialPreservesOthers(t *testing.T) {
	r, cfg, _ := newNTPProbeRouter(t)
	cfg.System.ExternalNTPProbeEnabled = false
	cfg.System.ExternalNTPServers = []string{"a", "b"}
	cfg.System.ExternalNTPProbeTimeout = 5 * time.Second

	body := `{"enabled":true}`
	req := httptest.NewRequest(http.MethodPut, "/api/system/ntp-probe-config", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if !cfg.System.ExternalNTPProbeEnabled {
		t.Fatalf("Enabled not flipped")
	}
	if len(cfg.System.ExternalNTPServers) != 2 || cfg.System.ExternalNTPProbeTimeout != 5*time.Second {
		t.Fatalf("partial PUT clobbered untouched fields: %+v", cfg.System)
	}
}

// TestNTPProbeConfig_PutEmptyServersClears: an explicit `[]` clears the
// list (versus omitting the key, which preserves it).
func TestNTPProbeConfig_PutEmptyServersClears(t *testing.T) {
	r, cfg, _ := newNTPProbeRouter(t)
	cfg.System.ExternalNTPServers = []string{"a", "b"}

	body := `{"servers":[]}`
	req := httptest.NewRequest(http.MethodPut, "/api/system/ntp-probe-config", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if len(cfg.System.ExternalNTPServers) != 0 {
		t.Fatalf("servers not cleared: %v", cfg.System.ExternalNTPServers)
	}
}

// TestNTPProbeConfig_PutValidatesTimeout: out-of-range timeoutSeconds
// must 400.
func TestNTPProbeConfig_PutValidatesTimeout(t *testing.T) {
	r, _, _ := newNTPProbeRouter(t)

	for _, v := range []int{0, -1, 31, 1000} {
		body := `{"timeoutSeconds":` + strconvItoa(v) + `}`
		req := httptest.NewRequest(http.MethodPut, "/api/system/ntp-probe-config", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("v=%d: status=%d, want 400", v, rr.Code)
		}
	}
}

// TestNTPProbeConfig_PutCapsServerCount: more than MaxNTPProbeServers
// distinct servers must 400.
func TestNTPProbeConfig_PutCapsServerCount(t *testing.T) {
	r, _, _ := newNTPProbeRouter(t)

	servers := make([]string, MaxNTPProbeServers+1)
	for i := range servers {
		servers[i] = "server" + strconvItoa(i) + ".example"
	}
	bodyMap := map[string]any{"servers": servers}
	bodyBytes, _ := json.Marshal(bodyMap)
	req := httptest.NewRequest(http.MethodPut, "/api/system/ntp-probe-config", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

// TestNTPProbeConfig_PutDedupesAndTrimsServers: whitespace + duplicate
// entries are normalised before persistence.
func TestNTPProbeConfig_PutDedupesAndTrimsServers(t *testing.T) {
	r, cfg, _ := newNTPProbeRouter(t)

	body := `{"servers":["  pool.ntp.org  ","POOL.NTP.ORG","time.cloudflare.com"," "]}`
	req := httptest.NewRequest(http.MethodPut, "/api/system/ntp-probe-config", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if len(cfg.System.ExternalNTPServers) != 2 {
		t.Fatalf("expected 2 deduped servers, got %v", cfg.System.ExternalNTPServers)
	}
	if cfg.System.ExternalNTPServers[0] != "pool.ntp.org" || cfg.System.ExternalNTPServers[1] != "time.cloudflare.com" {
		t.Fatalf("dedup wrong: %v", cfg.System.ExternalNTPServers)
	}
}

// TestNTPProbeConfig_PutRequiresAtLeastOneField: an empty body is a 400.
func TestNTPProbeConfig_PutRequiresAtLeastOneField(t *testing.T) {
	r, _, _ := newNTPProbeRouter(t)

	body := `{}`
	req := httptest.NewRequest(http.MethodPut, "/api/system/ntp-probe-config", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

// TestNTPProbeConfig_PutRejectsUnknownFields: typos in the body must
// fail loud, not silently.
func TestNTPProbeConfig_PutRejectsUnknownFields(t *testing.T) {
	r, _, _ := newNTPProbeRouter(t)

	body := `{"enbaled":true}` // typo
	req := httptest.NewRequest(http.MethodPut, "/api/system/ntp-probe-config", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

// TestNTPProbeConfig_OnApplyHook: the registered onApply callback is
// invoked with the post-PUT options (used by the agent to reset the
// heartbeat throttle).
func TestNTPProbeConfig_OnApplyHook(t *testing.T) {
	cfg := loadConfigForTest(t, minimalConfigYAML())
	timeH := NewSystemTimeHealthHandlerWithProbe(ExternalNTPProbeOptions{})
	h := NewSystemNTPProbeConfigHandler(cfg, timeH)

	var captured ExternalNTPProbeOptions
	called := 0
	h.SetOnApply(func(opts ExternalNTPProbeOptions) {
		captured = opts
		called++
	})

	r := chi.NewRouter()
	r.Put("/api/system/ntp-probe-config", h.Set)

	body := `{"enabled":true,"servers":["x.example"]}`
	req := httptest.NewRequest(http.MethodPut, "/api/system/ntp-probe-config", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if called != 1 {
		t.Fatalf("onApply called %d times, want 1", called)
	}
	if !captured.Enabled || len(captured.Servers) != 1 || captured.Servers[0] != "x.example" {
		t.Fatalf("captured opts wrong: %+v", captured)
	}
}

// strconvItoa avoids pulling strconv into the test imports just for one helper.
func strconvItoa(i int) string {
	if i == 0 {
		return "0"
	}
	negative := i < 0
	if negative {
		i = -i
	}
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}
