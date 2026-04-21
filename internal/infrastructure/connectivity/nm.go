// Package connectivity provides OS-level backends for the domain
// connectivity.Service interface.
//
// The NetworkManager backend (this file) drives WiFi client, ethernet and
// the local setup hotspot by shelling out to `nmcli`. We could in theory
// talk to NM via D-Bus directly but `nmcli` is stable across versions, easy
// to test and doesn't pin us to a specific NM major version.
//
// All nmcli calls go through `run()` which enforces a timeout and returns
// the raw output. Parsing is done with the `-t -f <fields>` terse form so
// we don't depend on human-readable column widths.
package connectivity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	cx "github.com/rud1-es/rud1-fw/internal/domain/connectivity"
)

// NMBackend drives WiFi + AP via NetworkManager (nmcli).
type NMBackend struct {
	wifiIface string // e.g. "wlan0"
	apSSID    string
	apPass    string
	apIface   string // usually same as wifiIface; NM can run AP and client on different radios if available
	apCIDR    string // e.g. "192.168.50.1/24"
	nmcli     string // resolved path, cached
}

// NMConfig bundles the knobs needed to construct an NMBackend.
type NMConfig struct {
	WiFiInterface string
	APSSID        string
	APPassword    string
	APInterface   string
	APCIDR        string
}

// NewNMBackend builds a backend. `nmcli` must be on PATH; if it isn't, the
// returned backend will report ErrUnavailable from every method so callers
// can fall back to the simulated implementation.
func NewNMBackend(c NMConfig) *NMBackend {
	b := &NMBackend{
		wifiIface: defaultStr(c.WiFiInterface, "wlan0"),
		apSSID:    defaultStr(c.APSSID, "Rud1-Setup"),
		apPass:    c.APPassword,
		apIface:   defaultStr(c.APInterface, c.WiFiInterface),
		apCIDR:    defaultStr(c.APCIDR, "192.168.50.1/24"),
	}
	if p, err := exec.LookPath("nmcli"); err == nil {
		b.nmcli = p
	}
	return b
}

// ErrUnavailable means NetworkManager isn't installed or reachable. Higher
// layers can catch it and serve simulated data.
var ErrUnavailable = errors.New("networkmanager unavailable (nmcli not found)")

func (b *NMBackend) Available() bool { return b.nmcli != "" }

// ── Public API used by the service layer ────────────────────────────────────

// Scan triggers a rescan and returns the freshest view. Side-effect free
// beyond the scan itself.
func (b *NMBackend) Scan(ctx context.Context) ([]cx.WiFiNetwork, error) {
	if !b.Available() {
		return nil, ErrUnavailable
	}
	// Best-effort rescan. If another rescan is in progress nmcli returns
	// non-zero; we ignore that and read the existing cache.
	_, _ = b.run(ctx, 8*time.Second, "device", "wifi", "rescan", "ifname", b.wifiIface)

	out, err := b.run(ctx, 6*time.Second,
		"-t", "-f", "IN-USE,BSSID,SSID,SECURITY,SIGNAL,FREQ,CHAN",
		"device", "wifi", "list", "ifname", b.wifiIface, "--rescan", "no",
	)
	if err != nil {
		return nil, err
	}

	saved, _ := b.Saved(ctx)
	savedSet := make(map[string]struct{}, len(saved))
	for _, s := range saved {
		savedSet[s.SSID] = struct{}{}
	}

	var nets []cx.WiFiNetwork
	for _, line := range splitNonEmpty(out) {
		f := splitNmcli(line, 7)
		if len(f) < 7 {
			continue
		}
		ssid := unescape(f[2])
		if ssid == "" {
			continue // hidden SSIDs show blank; skip until we support connecting to hidden
		}
		signalPct, _ := strconv.Atoi(f[4])
		freq, _ := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(f[5], "MHz")))
		ch, _ := strconv.Atoi(f[6])
		_, isSaved := savedSet[ssid]
		nets = append(nets, cx.WiFiNetwork{
			SSID:       ssid,
			BSSID:      f[1],
			Security:   normalizeSecurity(f[3]),
			SignalDBm:  pctToDBm(signalPct),
			SignalPct:  signalPct,
			FrequencyM: freq,
			Channel:    ch,
			InUse:      f[0] == "*",
			Saved:      isSaved,
		})
	}
	return nets, nil
}

// Saved returns the list of persisted WiFi connections (passwords never
// leave the device).
func (b *NMBackend) Saved(ctx context.Context) ([]cx.SavedWiFi, error) {
	if !b.Available() {
		return nil, ErrUnavailable
	}
	out, err := b.run(ctx, 4*time.Second,
		"-t", "-f", "NAME,TYPE,AUTOCONNECT,AUTOCONNECT-PRIORITY,TIMESTAMP",
		"connection", "show",
	)
	if err != nil {
		return nil, err
	}
	var saved []cx.SavedWiFi
	for _, line := range splitNonEmpty(out) {
		f := splitNmcli(line, 5)
		if len(f) < 5 || f[1] != "802-11-wireless" {
			continue
		}
		autoConnect := strings.EqualFold(f[2], "yes")
		prio, _ := strconv.Atoi(f[3])
		ts, _ := strconv.ParseInt(f[4], 10, 64)
		sec := b.readConnectionSecurity(ctx, f[0])
		saved = append(saved, cx.SavedWiFi{
			SSID:        f[0],
			Security:    sec,
			AutoConnect: autoConnect,
			Priority:    prio,
			LastUsed:    unixToTime(ts),
		})
	}
	return saved, nil
}

// Connect joins a WiFi network, persisting credentials. Returns an error
// with a stable prefix when auth fails (so the UI can show a helpful hint).
func (b *NMBackend) Connect(ctx context.Context, req cx.ConnectRequest) error {
	if !b.Available() {
		return ErrUnavailable
	}
	if req.SSID == "" {
		return errors.New("ssid required")
	}

	args := []string{"device", "wifi", "connect", req.SSID, "ifname", b.wifiIface}
	if req.Password != "" {
		args = append(args, "password", req.Password)
	}
	if req.Hidden {
		args = append(args, "hidden", "yes")
	}
	// nmcli blocks until association attempt resolves; give it a generous
	// timeout to handle slow DHCP leases.
	if _, err := b.run(ctx, 45*time.Second, args...); err != nil {
		if isSecretsFailure(err) {
			return fmt.Errorf("wifi auth failed: wrong password or unsupported security")
		}
		return fmt.Errorf("wifi connect: %w", err)
	}

	// Optional priority bump so this network auto-reconnects preferentially.
	if req.Priority > 0 {
		_, _ = b.run(ctx, 3*time.Second,
			"connection", "modify", req.SSID,
			"connection.autoconnect", "yes",
			"connection.autoconnect-priority", strconv.Itoa(req.Priority),
		)
	}
	return nil
}

// Disconnect drops the active WiFi association (but keeps saved creds).
func (b *NMBackend) Disconnect(ctx context.Context) error {
	if !b.Available() {
		return ErrUnavailable
	}
	_, err := b.run(ctx, 5*time.Second, "device", "disconnect", b.wifiIface)
	return err
}

// Forget deletes the saved connection profile, so it won't auto-reconnect.
func (b *NMBackend) Forget(ctx context.Context, ssid string) error {
	if !b.Available() {
		return ErrUnavailable
	}
	_, err := b.run(ctx, 4*time.Second, "connection", "delete", ssid)
	return err
}

// Status reports the active WiFi association.
func (b *NMBackend) Status(ctx context.Context) (*cx.WiFiStatus, error) {
	if !b.Available() {
		return nil, ErrUnavailable
	}
	enabled := true
	if out, err := b.run(ctx, 2*time.Second, "radio", "wifi"); err == nil {
		enabled = strings.EqualFold(strings.TrimSpace(out), "enabled")
	}

	st := &cx.WiFiStatus{Enabled: enabled, Interface: b.wifiIface}

	out, err := b.run(ctx, 3*time.Second,
		"-t", "-f", "DEVICE,TYPE,STATE,CONNECTION",
		"device", "status",
	)
	if err != nil {
		return st, nil
	}
	for _, line := range splitNonEmpty(out) {
		f := splitNmcli(line, 4)
		if len(f) < 4 {
			continue
		}
		if f[0] != b.wifiIface {
			continue
		}
		if f[2] == "connected" && f[3] != "" && f[3] != b.apSSID {
			st.ConnectedSSID = f[3]
		}
	}

	if st.ConnectedSSID != "" {
		if ipv4 := b.readIPv4(ctx, b.wifiIface); ipv4 != "" {
			st.IPv4 = ipv4
		}
		// Signal of active BSS.
		if out, err := b.run(ctx, 3*time.Second,
			"-t", "-f", "IN-USE,SIGNAL,FREQ",
			"device", "wifi", "list", "ifname", b.wifiIface, "--rescan", "no",
		); err == nil {
			for _, line := range splitNonEmpty(out) {
				f := splitNmcli(line, 3)
				if len(f) >= 3 && f[0] == "*" {
					st.SignalPct, _ = strconv.Atoi(f[1])
					st.Frequency, _ = strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(f[2], "MHz")))
					break
				}
			}
		}
	}
	return st, nil
}

// ── AP ──────────────────────────────────────────────────────────────────────

const apConnectionName = "rud1-setup-ap"

// APEnable raises the setup hotspot. Idempotent: bringing it up while
// already active just re-applies the password.
func (b *NMBackend) APEnable(ctx context.Context) error {
	if !b.Available() {
		return ErrUnavailable
	}
	if b.apPass == "" {
		return errors.New("ap password is empty; refusing to start an open hotspot")
	}

	// Delete stale profile so we re-create with current SSID/password.
	_, _ = b.run(ctx, 2*time.Second, "connection", "delete", apConnectionName)

	args := []string{
		"connection", "add",
		"type", "wifi",
		"ifname", b.apIface,
		"con-name", apConnectionName,
		"autoconnect", "no",
		"ssid", b.apSSID,
		"mode", "ap",
		"802-11-wireless.band", "bg", // 2.4 GHz for phone compatibility
		"ipv4.method", "shared",
		"ipv4.addresses", b.apCIDR,
		"wifi-sec.key-mgmt", "wpa-psk",
		"wifi-sec.psk", b.apPass,
	}
	if _, err := b.run(ctx, 10*time.Second, args...); err != nil {
		return fmt.Errorf("ap add: %w", err)
	}
	if _, err := b.run(ctx, 20*time.Second, "connection", "up", apConnectionName); err != nil {
		return fmt.Errorf("ap up: %w", err)
	}
	return nil
}

// APDisable tears the hotspot down.
func (b *NMBackend) APDisable(ctx context.Context) error {
	if !b.Available() {
		return ErrUnavailable
	}
	_, _ = b.run(ctx, 5*time.Second, "connection", "down", apConnectionName)
	_, _ = b.run(ctx, 3*time.Second, "connection", "delete", apConnectionName)
	return nil
}

// APStatus reports whether the hotspot profile is currently active.
func (b *NMBackend) APStatus(ctx context.Context) (*cx.APStatus, error) {
	s := &cx.APStatus{
		SSID:      b.apSSID,
		Password:  b.apPass,
		Interface: b.apIface,
	}
	if !b.Available() {
		return s, nil
	}
	out, err := b.run(ctx, 3*time.Second,
		"-t", "-f", "NAME,DEVICE,STATE",
		"connection", "show", "--active",
	)
	if err != nil {
		return s, nil
	}
	for _, line := range splitNonEmpty(out) {
		f := splitNmcli(line, 3)
		if len(f) >= 3 && f[0] == apConnectionName && f[2] == "activated" {
			s.Active = true
			s.IPv4 = strings.SplitN(b.apCIDR, "/", 2)[0]
			break
		}
	}
	return s, nil
}

// ── helpers ─────────────────────────────────────────────────────────────────

func (b *NMBackend) readConnectionSecurity(ctx context.Context, name string) cx.Security {
	out, err := b.run(ctx, 2*time.Second,
		"-t", "-f", "802-11-wireless-security.key-mgmt",
		"connection", "show", name,
	)
	if err != nil {
		return cx.SecurityUnknown
	}
	val := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "802-11-wireless-security.key-mgmt:")))
	switch {
	case val == "" || val == "--":
		return cx.SecurityOpen
	case strings.Contains(val, "sae"):
		return cx.SecurityWPA3
	case strings.Contains(val, "wpa-eap") || strings.Contains(val, "ieee8021x"):
		return cx.SecurityEAP
	case strings.Contains(val, "wpa"):
		return cx.SecurityWPA2
	default:
		return cx.SecurityUnknown
	}
}

func (b *NMBackend) readIPv4(ctx context.Context, iface string) string {
	out, err := b.run(ctx, 2*time.Second,
		"-t", "-f", "IP4.ADDRESS", "device", "show", iface,
	)
	if err != nil {
		return ""
	}
	for _, line := range splitNonEmpty(out) {
		if !strings.HasPrefix(line, "IP4.ADDRESS") {
			continue
		}
		_, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		// nmcli prints "192.168.1.5/24"
		return strings.SplitN(strings.TrimSpace(v), "/", 2)[0]
	}
	return ""
}

func (b *NMBackend) run(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx2, b.nmcli, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Debug().Str("cmd", "nmcli "+strings.Join(args, " ")).
			Str("stderr", strings.TrimSpace(stderr.String())).
			Err(err).Msg("nmcli invocation failed")
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func splitNmcli(line string, n int) []string {
	// nmcli -t uses ':' as separator and escapes literal ':' as '\:'.
	out := make([]string, 0, n)
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '\\' && i+1 < len(line) && line[i+1] == ':' {
			cur.WriteByte(':')
			i++
			continue
		}
		if ch == ':' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(ch)
	}
	out = append(out, cur.String())
	return out
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimRight(l, "\r")
		if l == "" {
			continue
		}
		out = append(out, l)
	}
	return out
}

func unescape(s string) string {
	// nmcli escapes backslashes in -t mode.
	return strings.ReplaceAll(s, `\\`, `\`)
}

func normalizeSecurity(s string) cx.Security {
	v := strings.ToUpper(strings.TrimSpace(s))
	switch {
	case v == "" || v == "--":
		return cx.SecurityOpen
	case strings.Contains(v, "WPA3") || strings.Contains(v, "SAE"):
		return cx.SecurityWPA3
	case strings.Contains(v, "WPA2"):
		return cx.SecurityWPA2
	case strings.Contains(v, "WPA"):
		return cx.SecurityWPA
	case strings.Contains(v, "WEP"):
		return cx.SecurityWEP
	case strings.Contains(v, "802.1X") || strings.Contains(v, "EAP"):
		return cx.SecurityEAP
	default:
		return cx.SecurityUnknown
	}
}

func pctToDBm(pct int) int {
	// NM exposes quality percentage, not raw dBm. Approximate mapping:
	// 100% ≈ -40 dBm, 0% ≈ -95 dBm. Monotonic and good enough for the UI.
	if pct <= 0 {
		return -95
	}
	if pct >= 100 {
		return -40
	}
	return -95 + (pct * 55 / 100)
}

func isSecretsFailure(err error) bool {
	s := err.Error()
	return strings.Contains(s, "Secrets were required") ||
		strings.Contains(s, "property-missing") ||
		strings.Contains(s, "invalid passphrase") ||
		strings.Contains(strings.ToLower(s), "no network with ssid")
}

func defaultStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func unixToTime(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}
