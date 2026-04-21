// ModemManager backend for the cellular modem (Sierra Wireless AirPrime
// MC7700 on the "HAT" SIM carrier for the Raspberry Pi).
//
// Everything is driven via `mmcli`, which ModemManager exposes as a stable
// CLI wrapper over its D-Bus API. The MC7700 is a 3G/LTE USB-attached modem
// that appears as several ttyUSB devices plus a network interface (cdc-wdm
// / wwanX). On modern kernels ModemManager auto-detects and manages it.
//
// IMPORTANT: every `mmcli` call here has been designed against the
// documented mmcli output, but it has NOT been end-to-end validated on real
// MC7700 hardware yet. Treat this file as the contract + skeleton and
// expect to iterate once the HAT is bench-tested.
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

// MMBackend talks to ModemManager via mmcli.
type MMBackend struct {
	mmcli string
	// Optional: iface naming varies (wwan0, cdc-wdm0, wwx*). We read it
	// from mmcli status; no hard-coding needed.
}

// NewMMBackend resolves `mmcli` on PATH. If missing, .Available() returns
// false and every call errors with ErrUnavailable — callers should fall
// back to reporting Present=false.
func NewMMBackend() *MMBackend {
	b := &MMBackend{}
	if p, err := exec.LookPath("mmcli"); err == nil {
		b.mmcli = p
	}
	return b
}

func (b *MMBackend) Available() bool { return b.mmcli != "" }

// Status returns a snapshot of the (first) modem mmcli knows about.
func (b *MMBackend) Status(ctx context.Context) (*cx.CellularStatus, error) {
	if !b.Available() {
		return &cx.CellularStatus{Present: false, SIMState: cx.SIMUnknown}, nil
	}

	modemIdx, err := b.firstModemIndex(ctx)
	if err != nil || modemIdx == "" {
		return &cx.CellularStatus{Present: false, SIMState: cx.SIMAbsent}, nil
	}

	st := &cx.CellularStatus{Present: true, SIMState: cx.SIMUnknown}

	out, err := b.run(ctx, 4*time.Second, "-K", "-m", modemIdx)
	if err != nil {
		return st, nil
	}
	kv := parseMMCLIKV(out)

	st.Manufacturer = kv["modem.generic.manufacturer"]
	st.Model = kv["modem.generic.model"]
	st.Firmware = kv["modem.generic.revision"]
	st.IMEI = kv["modem.generic.equipment-identifier"]
	st.Operator = kv["modem.3gpp.operator-name"]
	st.OperatorCode = kv["modem.3gpp.operator-code"]
	st.NetworkType = extractAccessTech(kv["modem.generic.access-technologies.value[1]"])
	st.Interface = kv["modem.generic.primary-port"]

	if raw := kv["modem.generic.signal-quality.value"]; raw != "" {
		pct, _ := strconv.Atoi(strings.TrimSpace(raw))
		st.SignalPct = pct
		st.SignalDBm = pctToDBm(pct)
	}

	switch strings.ToLower(kv["modem.generic.state"]) {
	case "connected":
		st.Connected = true
	case "registered":
		// Connected to tower but no bearer — treat as not-yet-connected.
	}

	st.Roaming = strings.EqualFold(kv["modem.3gpp.registration-state"], "roaming")

	// SIM
	simPath := kv["modem.generic.sim"]
	if simPath != "" && simPath != "--" {
		simOut, err := b.run(ctx, 3*time.Second, "-K", "-i", simPath)
		if err == nil {
			skv := parseMMCLIKV(simOut)
			st.IMSI = skv["sim.properties.imsi"]
		}
	}
	st.SIMState = parseSIMState(kv["modem.generic.unlock-required"], kv["modem.generic.state"])

	// Bearer IP info
	if bearerPath := kv["modem.generic.bearers.value[1]"]; bearerPath != "" && bearerPath != "--" {
		bOut, err := b.run(ctx, 3*time.Second, "-K", "-b", bearerPath)
		if err == nil {
			bkv := parseMMCLIKV(bOut)
			st.IPv4 = bkv["bearer.ipv4-config.address"]
			st.APN = bkv["bearer.properties.apn"]
		}
	}

	// Counters (opt-in; mmcli --simple-status exposes RSSI but not bytes;
	// real counters come from the kernel wwanX interface). We leave 0 here
	// and let the network scanner populate from /sys/class/net stats when
	// the bearer is up.
	return st, nil
}

// Connect brings up the cellular bearer with the currently persisted APN.
// If no APN is persisted, the caller should SetConfig first.
func (b *MMBackend) Connect(ctx context.Context, apn, user, pass string) error {
	if !b.Available() {
		return ErrUnavailable
	}
	idx, err := b.firstModemIndex(ctx)
	if err != nil {
		return err
	}
	if idx == "" {
		return errors.New("no modem detected")
	}

	args := []string{"-m", idx, "--simple-connect"}
	if apn != "" {
		keypairs := []string{"apn=" + apn}
		if user != "" {
			keypairs = append(keypairs, "user="+user)
		}
		if pass != "" {
			keypairs = append(keypairs, "password="+pass)
		}
		args = append(args, strings.Join(keypairs, ","))
	}
	_, err = b.run(ctx, 60*time.Second, args...)
	return err
}

// Disconnect drops any active cellular bearer.
func (b *MMBackend) Disconnect(ctx context.Context) error {
	if !b.Available() {
		return ErrUnavailable
	}
	idx, err := b.firstModemIndex(ctx)
	if err != nil || idx == "" {
		return nil
	}
	_, err = b.run(ctx, 15*time.Second, "-m", idx, "--simple-disconnect")
	return err
}

// UnlockPIN sends the PIN to a locked SIM. Returns an error whose message
// includes remaining attempts when mmcli reports them.
func (b *MMBackend) UnlockPIN(ctx context.Context, pin string) error {
	if !b.Available() {
		return ErrUnavailable
	}
	if len(pin) < 4 || len(pin) > 8 {
		return errors.New("pin must be 4–8 digits")
	}
	idx, err := b.firstModemIndex(ctx)
	if err != nil || idx == "" {
		return errors.New("no modem detected")
	}
	// First grab the SIM path (needed by mmcli --pin).
	mOut, err := b.run(ctx, 3*time.Second, "-K", "-m", idx)
	if err != nil {
		return err
	}
	sim := parseMMCLIKV(mOut)["modem.generic.sim"]
	if sim == "" || sim == "--" {
		return errors.New("no SIM detected")
	}
	_, err = b.run(ctx, 10*time.Second, "-i", sim, "--pin", pin)
	return err
}

// ── helpers ────────────────────────────────────────────────────────────────

func (b *MMBackend) firstModemIndex(ctx context.Context) (string, error) {
	out, err := b.run(ctx, 3*time.Second, "-L")
	if err != nil {
		return "", err
	}
	// Output lines look like:
	//     /org/freedesktop/ModemManager1/Modem/0 [Sierra Wireless, Incorporated] MC7700
	for _, line := range splitNonEmpty(out) {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "/Modem/") {
			continue
		}
		slash := strings.LastIndex(line, "/Modem/")
		if slash < 0 {
			continue
		}
		rest := line[slash+len("/Modem/"):]
		idxEnd := strings.IndexAny(rest, " \t")
		if idxEnd < 0 {
			idxEnd = len(rest)
		}
		return rest[:idxEnd], nil
	}
	return "", nil
}

// parseMMCLIKV parses `mmcli -K` key=value output. Keys are dotted and
// repeated keys use `[N]` suffixes.
func parseMMCLIKV(s string) map[string]string {
	out := map[string]string{}
	for _, line := range splitNonEmpty(s) {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func parseSIMState(unlockRequired, modemState string) cx.SIMState {
	switch strings.ToLower(strings.TrimSpace(unlockRequired)) {
	case "", "--", "none":
		// Not waiting on any code — look at the modem state next.
		if strings.EqualFold(modemState, "failed") {
			return cx.SIMFailure
		}
		return cx.SIMUnlocked
	case "sim-pin":
		return cx.SIMLocked
	case "sim-puk":
		return cx.SIMPUK
	default:
		return cx.SIMUnknown
	}
}

func extractAccessTech(s string) string {
	// mmcli prints access technologies as an array; we take the first entry.
	s = strings.TrimSpace(s)
	if s == "" || s == "--" {
		return ""
	}
	return strings.ToLower(s)
}

func (b *MMBackend) run(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx2, b.mmcli, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Debug().Str("cmd", "mmcli "+strings.Join(args, " ")).
			Str("stderr", strings.TrimSpace(stderr.String())).
			Err(err).Msg("mmcli invocation failed")
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
