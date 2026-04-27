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
	apCountry string // ISO-3166 alpha-2 (e.g. "ES") for the kernel reg domain
	nmcli     string // resolved path, cached
}

// NMConfig bundles the knobs needed to construct an NMBackend.
type NMConfig struct {
	WiFiInterface string
	APSSID        string
	APPassword    string
	APInterface   string
	APCIDR        string
	APCountry     string
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
		apCountry: defaultStr(c.APCountry, "ES"),
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
//
// Any pre-existing connection profile with the same SSID is deleted first.
// `nmcli device wifi connect` reuses an existing profile when one matches
// by name, which is fine when that profile is healthy — but a previous
// connect attempt that aborted before NM finished writing the security
// section leaves behind a profile with no `802-11-wireless-security.*`
// keys. From then on every retry fails with
//
//	Error: 802-11-wireless-security.key-mgmt: property is missing.
//
// because nmcli keeps reusing the broken profile and never rebuilds it
// from the scan beacon. Wiping it before each call makes Connect
// deterministic: the password the operator just typed is the only thing
// that decides success/failure, regardless of past failed attempts.
func (b *NMBackend) Connect(ctx context.Context, req cx.ConnectRequest) error {
	if !b.Available() {
		return ErrUnavailable
	}
	if req.SSID == "" {
		return errors.New("ssid required")
	}

	// Best-effort cleanup of stale profiles. `nmcli connection delete`
	// returns non-zero when no match exists; swallow that — there's
	// nothing to clean and we still want to attempt the connect.
	_, _ = b.run(ctx, 3*time.Second, "connection", "delete", req.SSID)

	// Build the profile EXPLICITLY rather than via `nmcli device wifi
	// connect`. The high-level command infers `wifi-sec.key-mgmt` from
	// the live scan beacon, so it fails when the SSID isn't currently
	// visible (stale scan / weak signal / momentary AP outage) with:
	//
	//   Error: 802-11-wireless-security.key-mgmt: property is missing.
	//
	// Building the profile by hand makes the call deterministic — the
	// password the operator typed is the only thing that decides
	// success or failure. Mirrors the AP-mode setup below which has
	// always built profiles this way for the same reason.
	addArgs := []string{
		"connection", "add",
		"type", "wifi",
		"ifname", b.wifiIface,
		"con-name", req.SSID,
		"ssid", req.SSID,
		"connection.autoconnect", "yes",
	}
	if req.Hidden {
		addArgs = append(addArgs, "802-11-wireless.hidden", "yes")
	}
	if req.Password != "" {
		// WPA2-PSK is the de-facto home-router default and what every
		// SSID-with-password setup we ship today targets. WPA2/WPA3
		// mixed-mode APs accept `wpa-psk` because they negotiate down
		// to WPA2-PSK for clients that don't offer SAE. Pure WPA3-SAE
		// networks would need `sae` here — out of scope for now;
		// document as a known limitation if a customer hits it.
		addArgs = append(addArgs,
			"wifi-sec.key-mgmt", "wpa-psk",
			"wifi-sec.psk", req.Password,
		)
	}

	if _, err := b.run(ctx, 8*time.Second, addArgs...); err != nil {
		// `connection add` failures are usually argument-parsing on
		// our side (e.g. SSID with characters nmcli's shell-style arg
		// parser hates). Log loudly so the operator sees the cause.
		log.Warn().Str("ssid", req.SSID).Err(err).Msg("wifi profile add failed")
		return fmt.Errorf("wifi profile add: %w", err)
	}

	// `connection up` does the actual association + DHCP. Generous
	// timeout because some routers take a beat to associate and DHCP
	// can be slow on the first lease of a new client.
	if _, err := b.run(ctx, 45*time.Second, "connection", "up", req.SSID); err != nil {
		log.Warn().Str("ssid", req.SSID).Err(err).Msg("wifi connect failed")
		// On failure, drop the half-broken profile so the next attempt
		// starts clean. Best-effort — `connection delete` will fail
		// silently if the row was already removed by NM during its
		// own teardown after the failed up.
		_, _ = b.run(ctx, 3*time.Second, "connection", "delete", req.SSID)

		if isNotVisibleFailure(err) {
			// SSID is not in nmcli's current scan cache. Most often: a stale
			// scan, the AP is on a band/channel the radio isn't currently on,
			// or the SSID has subtle whitespace/unicode that didn't survive
			// some upstream string handling.
			return fmt.Errorf("wifi network %q not visible — try rescanning", req.SSID)
		}
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

const (
	apConnectionName = "rud1-setup-ap"
	// apChannel pins the AP to 2.4 GHz channel 6 — universally supported
	// by every WiFi-capable phone in the last 15 years (no DFS, no UE-only
	// 12/13, no driver edge cases). The Pi 3 onboard radio is 2.4 GHz only
	// anyway; locking to a known-good channel keeps clients from chasing
	// NM's auto-pick.
	apChannel = "6"
)

// APEnable raises the setup hotspot. Idempotent in the strong sense: when
// the profile is already active the call is a no-op, so the supervisor's
// per-tick re-evaluation never tears down a working association.
//
// Compatibility knobs locked in:
//
//   - 2.4 GHz band, fixed channel 6, hidden=no
//   - WPA2-PSK only (proto=rsn, pairwise=ccmp, group=ccmp) — refuses to
//     fall back to WPA1/TKIP, which kills modern Android clients.
//   - PMF disabled — Protected Management Frames are optional/required by
//     default in NM ≥ 1.40 and break legacy phones (Android 9 and older,
//     some Samsung firmwares) that have no 802.11w support.
//   - ipv4.method=shared — NM's built-in dnsmasq serves DHCP + DNS on the
//     AP subnet so any phone gets an IP and can resolve the panel.
//
// PiOS Lite gotchas defended against:
//
//   - rfkill soft-block (cleared up front).
//   - Missing reg domain: country 00 means the radio refuses to broadcast.
//     ensureRegulatoryDomain applies APCountry (default "ES") if unset.
//   - nmcli noisy errors: stderr is surfaced at warn level on failure.
func (b *NMBackend) APEnable(ctx context.Context) error {
	if !b.Available() {
		return ErrUnavailable
	}
	if b.apPass == "" {
		return errors.New("ap password is empty; refusing to start an open hotspot")
	}

	// Idempotency fast-path: a profile that's already activated is left
	// alone. This is what stops the supervisor from cycling the AP every
	// 15-second tick and dropping every connected phone in the process.
	if b.isAPActive(ctx) {
		return nil
	}

	// Best-effort radio unblock. `rfkill` is in raspberrypi-sys-mods on PiOS
	// but might be absent on minimal images; we don't fail if the binary or
	// the command itself errors out — `nmcli radio wifi on` below is a
	// second line of defence.
	b.bestEffortUnblockWiFi(ctx)
	// Make sure NM's own radio toggle is on too. Same idempotent-best-effort
	// philosophy: if this fails because radio is already on, who cares.
	_, _ = b.run(ctx, 2*time.Second, "radio", "wifi", "on")
	// Apply a regulatory domain if the kernel still has the empty default.
	// Without this nmcli reports "connection up" but no channel is actually
	// broadcast and phones never see the SSID.
	b.ensureRegulatoryDomain(ctx)

	// Delete stale profile so we re-create with current SSID/password.
	// Note: this only deletes our OWN profile (apConnectionName) — never
	// foreign profiles, even if they're squatting on wlan0. Removing a
	// user's saved client SSID would be a hostile surprise.
	_, _ = b.run(ctx, 2*time.Second, "connection", "delete", apConnectionName)

	args := []string{
		"connection", "add",
		"type", "wifi",
		"ifname", b.apIface,
		"con-name", apConnectionName,
		"autoconnect", "no",
		"ssid", b.apSSID,
		"mode", "ap",
		"802-11-wireless.band", "bg",
		"802-11-wireless.channel", apChannel,
		"802-11-wireless.hidden", "no",
		"ipv4.method", "shared",
		"ipv4.addresses", b.apCIDR,
		"wifi-sec.key-mgmt", "wpa-psk",
		"wifi-sec.proto", "rsn",
		"wifi-sec.pairwise", "ccmp",
		"wifi-sec.group", "ccmp",
		"wifi-sec.pmf", "1",
		"wifi-sec.psk", b.apPass,
	}
	if _, err := b.run(ctx, 10*time.Second, args...); err != nil {
		return fmt.Errorf("ap add: %w", err)
	}
	if _, err := b.run(ctx, 20*time.Second, "connection", "up", apConnectionName); err != nil {
		// The run() helper already logs at debug level — re-emit at warn
		// so the operator sees the failure without flipping log_level.
		log.Warn().
			Err(err).
			Str("connection", apConnectionName).
			Str("interface", b.apIface).
			Msg("nmcli connection up failed for setup AP")
		return fmt.Errorf("ap up: %w", err)
	}
	return nil
}

// isAPActive returns true when our setup-AP profile is currently in the
// "activated" state per NetworkManager. A transient nmcli failure is
// treated as "not active" so the caller takes the recreate path — that's
// the safe direction (an extra recreate beats a phantom "AP looks fine"
// when it really isn't).
func (b *NMBackend) isAPActive(ctx context.Context) bool {
	out, err := b.run(ctx, 3*time.Second,
		"-t", "-f", "NAME,STATE",
		"connection", "show", "--active",
	)
	if err != nil {
		return false
	}
	for _, line := range splitNonEmpty(out) {
		f := splitNmcli(line, 2)
		if len(f) >= 2 && f[0] == apConnectionName && f[1] == "activated" {
			return true
		}
	}
	return false
}

// bestEffortUnblockWiFi calls `rfkill unblock wifi` so the radio is usable.
// PiOS Lite leaves wlan0 soft-blocked on first boot until a regulatory
// domain is set — if we don't unblock here, `nmcli connection up` returns
// a generic activation error and the installer is left guessing.
//
// Failures are intentionally swallowed: rfkill may not be installed, or
// the user may have a non-Pi image where the radio is already unblocked.
// In either case the subsequent `connection up` is the source of truth.
func (b *NMBackend) bestEffortUnblockWiFi(ctx context.Context) {
	rfkill, err := exec.LookPath("rfkill")
	if err != nil {
		return
	}
	ctx2, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx2, rfkill, "unblock", "wifi")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Debug().
			Err(err).
			Str("stderr", strings.TrimSpace(stderr.String())).
			Msg("rfkill unblock wifi failed (non-fatal)")
	}
}

// ensureRegulatoryDomain reads `iw reg get` and, if the kernel still
// reports the empty default (country 00), applies b.apCountry. A unset
// regdom is the most common reason the AP "starts" but no phone sees it
// — the radio is up but the kernel refuses to pick a channel under
// world-roaming rules.
//
// This used to be a warn-only probe; now we actually fix it. Failures are
// logged at warn so the operator can spot a missing `iw` or a kernel that
// rejects the country code, but they don't block the AP bring-up — the
// subsequent `connection up` will surface the real symptom.
func (b *NMBackend) ensureRegulatoryDomain(ctx context.Context) {
	iw, err := exec.LookPath("iw")
	if err != nil {
		// `iw` not installed — common on minimal images. We can't check
		// or fix; the AP may still work if NM's defaults are good enough.
		return
	}

	country := b.apCountry
	if country == "" {
		country = "ES"
	}

	ctx2, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx2, iw, "reg", "get").Output()
	if err != nil {
		return
	}

	// `iw reg get` prints one or more "country XX: ..." blocks. We treat
	// the first one as authoritative — if it's "00" or empty we apply.
	needSet := true
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "country ") {
			continue
		}
		rest := strings.TrimPrefix(line, "country ")
		code, _, _ := strings.Cut(rest, ":")
		code = strings.TrimSpace(code)
		if code != "" && code != "00" {
			needSet = false
		}
		break
	}
	if !needSet {
		return
	}

	log.Warn().
		Str("country", country).
		Msg("wireless regulatory domain unset (country 00) — applying default so the AP can broadcast")
	ctx3, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx3, iw, "reg", "set", country).Run(); err != nil {
		log.Warn().Err(err).Str("country", country).
			Msg("iw reg set failed — AP may still not broadcast. " +
				"Set wireless_country in config.yaml or run `sudo raspi-config nonint do_wifi_country <CC>`.")
	}
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

// APSetCredentials updates the SSID and password the AP will use on its
// next bring-up. If the AP is currently active it is reapplied in-place so
// connected clients see the new credentials immediately. An empty ssid
// keeps the current one.
func (b *NMBackend) APSetCredentials(ctx context.Context, ssid, password string) error {
	if !b.Available() {
		return ErrUnavailable
	}
	if ssid != "" {
		b.apSSID = ssid
	}
	b.apPass = password

	// If the AP is up, force a recreate. APEnable's idempotency check
	// would otherwise short-circuit the rebuild and the new PSK/SSID would
	// only land on the next supervisor bounce. Tearing the profile down
	// first makes APEnable take the recreate branch deterministically.
	if b.isAPActive(ctx) {
		_, _ = b.run(ctx, 3*time.Second, "connection", "delete", apConnectionName)
		return b.APEnable(ctx)
	}
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

// isSecretsFailure matches nmcli stderr lines that mean "the password (or
// key-mgmt) we supplied was rejected by the AP". Distinct from
// isNotVisibleFailure — that one means we never even tried to authenticate.
func isSecretsFailure(err error) bool {
	s := err.Error()
	return strings.Contains(s, "Secrets were required") ||
		strings.Contains(s, "property-missing") ||
		strings.Contains(s, "invalid passphrase")
}

// isNotVisibleFailure matches the nmcli error returned when the requested
// SSID is absent from the current scan cache. This is NOT an auth failure
// and must be surfaced separately so the operator knows to rescan or check
// for whitespace/unicode in the SSID rather than retyping the password.
func isNotVisibleFailure(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "no network with ssid")
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
