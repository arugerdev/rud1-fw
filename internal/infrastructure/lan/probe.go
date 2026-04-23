package lan

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/platform"
)

// PingOptions tunes a single probe run. Zero values fall back to DefaultPingOptions
// so callers that don't care about tuning can pass `PingOptions{}`.
type PingOptions struct {
	Count          int           // -c N, defaults to 3 when <= 0
	PerPingTimeout time.Duration // -W seconds, defaults to 2s when <= 0
}

// DefaultPingOptions mirrors the historical `-c 3 -W 2` invocation so existing
// callers that don't care about tuning keep the same behaviour.
func DefaultPingOptions() PingOptions {
	return PingOptions{Count: 3, PerPingTimeout: 2 * time.Second}
}

// PingResult is the outcome of a single /api/lan/probe call.
//
// RttMs is the average RTT reported by `ping` (0 when the target is
// unreachable or we could not parse the summary). PacketLoss is a fraction
// in [0.0, 1.0] (e.g. 0.33 for "1 packet of 3 lost"). Raw holds the first
// 512 bytes of the command's combined output so rud1-app can surface the
// underlying tool message for debugging without shipping megabytes of log.
type PingResult struct {
	Target      string  `json:"target"`
	Reachable   bool    `json:"reachable"`
	RttMs       float64 `json:"rttMs"`
	PacketLoss  float64 `json:"packetLoss"`
	PacketsSent int     `json:"packetsSent"`
	PacketsRecv int     `json:"packetsRecv"`
	Raw         string  `json:"raw"`
}

// Prober runs reachability probes against a LAN host. It is stateless; the
// struct exists so the wiring in agent.go matches the pattern used by the
// other infrastructure services and so we can extend it later (traceroute,
// ARP lookups, …) without a breaking API change.
type Prober struct{}

// targetRegexp mirrors the validation contract in the task: hostnames up to
// 254 chars using [A-Za-z0-9.-], IPv4 dotted quads, or IPv6 addresses
// without brackets. We deliberately reject anything that could smuggle a
// shell metachar (`;`, `|`, `` ` ``, `$`, spaces…) even though we pass args
// directly to exec.Command — defence in depth keeps future refactors safe.
var targetRegexp = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.\-:]{0,252}[a-zA-Z0-9])?$`)

// ValidateTarget reports whether s is a legal ping target (hostname, IPv4,
// or IPv6 without brackets). The regex in the task spec is
// `^[a-zA-Z0-9]([a-zA-Z0-9.\-]{0,252}[a-zA-Z0-9])?$`; we widen the middle
// class with `:` so IPv6 literals pass, matching the "or IPv6 without
// brackets" half of the spec.
func ValidateTarget(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("target is required")
	}
	if len(s) > 254 {
		return fmt.Errorf("target too long (%d chars)", len(s))
	}
	if !targetRegexp.MatchString(s) {
		return fmt.Errorf("target %q contains invalid characters", s)
	}
	return nil
}

// Regexes reused across Ping calls. The ping summary line looks like:
//
//	rtt min/avg/max/mdev = 1.234/23.456/78.9/12.3 ms
//
// iputils uses "rtt", busybox uses "round-trip"; accept both.
var (
	rttRegexp  = regexp.MustCompile(`(?:rtt|round-trip)\s+min/avg/max(?:/mdev)?\s*=\s*[0-9.]+/([0-9.]+)/`)
	lossRegexp = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)\s*%\s*packet loss`)
)

// rawLimit is how many bytes of the command's combined output we echo back
// to the HTTP caller. 512B fits 3-packet ping summaries comfortably while
// keeping the JSON response cheap.
const rawLimit = 512

// Ping runs `ping -c 3 -W 2 -q <target>` and parses the summary line. On
// Windows / RUD1_SIMULATE=1 we skip exec entirely and synthesise a
// deterministic "reachable" result so rud1-app's Connect tab still has
// something sensible to render during local development.
//
// The provided ctx is used verbatim — the HTTP layer owns the timeout so
// the probe aborts promptly if the caller disconnects.
func (p *Prober) Ping(ctx context.Context, target string, opts PingOptions) (*PingResult, error) {
	if err := ValidateTarget(target); err != nil {
		return nil, err
	}
	target = strings.TrimSpace(target)

	count := opts.Count
	if count <= 0 {
		count = 3
	}
	// -W is seconds; clamp to >=1s so sub-second timeouts don't underflow.
	perPingSec := int(opts.PerPingTimeout / time.Second)
	if opts.PerPingTimeout > 0 && opts.PerPingTimeout%time.Second != 0 {
		// Round non-integer seconds up so the operator's intent of
		// "at least N ms" isn't silently truncated.
		perPingSec++
	}
	if perPingSec < 1 {
		perPingSec = 2
	}

	if platform.SimulateHardware() {
		return simulatePing(target, count), nil
	}

	// iputils on Debian/RPi: -c count, -W per-packet timeout (s), -q summary only.
	cmd := exec.CommandContext(ctx, "ping",
		"-c", strconv.Itoa(count),
		"-W", strconv.Itoa(perPingSec),
		"-q", target)
	out, err := cmd.CombinedOutput()

	res := &PingResult{Target: target, PacketsSent: count, Raw: truncateRaw(out)}

	// Parse the summary regardless of exit code: ping exits non-zero when
	// packets are lost, but we still want the partial stats on the way out.
	text := string(out)
	if m := lossRegexp.FindStringSubmatch(text); len(m) == 2 {
		if v, perr := strconv.ParseFloat(m[1], 64); perr == nil {
			res.PacketLoss = clampFraction(v / 100.0)
		}
	} else if err != nil {
		// No summary at all (DNS failure, permission error…) — assume total loss.
		res.PacketLoss = 1.0
	}
	if m := rttRegexp.FindStringSubmatch(text); len(m) == 2 {
		if v, perr := strconv.ParseFloat(m[1], 64); perr == nil {
			res.RttMs = v
		}
	}

	res.Reachable = res.PacketLoss < 1.0
	if !res.Reachable {
		// Zero the RTT on full loss so the UI doesn't display a stale value
		// (it can happen when a summary line arrives with 100% loss and
		// avg=0.000, but we want to be explicit).
		res.RttMs = 0
	}
	// Derive received count from loss fraction. Rounded to nearest int so
	// busybox's truncated percentages (e.g. 33% of 3 = 2 received) match reality.
	received := int(float64(count)*(1.0-res.PacketLoss) + 0.5)
	if received < 0 {
		received = 0
	}
	if received > count {
		received = count
	}
	res.PacketsRecv = received
	return res, nil
}

// simulatePing produces a deterministic fake result keyed by the target so
// repeated calls from the same dev machine give stable numbers (handy when
// eyeballing the UI). Reachable is always true in sim mode. count is echoed
// into the Raw line so callers can tell the simulator honoured the option.
func simulatePing(target string, count int) *PingResult {
	sum := sha256.Sum256([]byte(target))
	// Map the first 8 bytes onto [5, 50] ms with sub-ms resolution.
	bits := binary.BigEndian.Uint64(sum[:8])
	rtt := 5.0 + float64(bits%45000)/1000.0
	log.Debug().
		Str("target", target).
		Float64("rtt_ms", rtt).
		Int("count", count).
		Bool("simulated", true).
		Msg("lan: ping (simulated)")
	return &PingResult{
		Target:      target,
		Reachable:   true,
		RttMs:       rtt,
		PacketLoss:  0,
		PacketsSent: count,
		PacketsRecv: count,
		Raw:         fmt.Sprintf("simulated=true target=%s count=%d rtt=%.3fms", target, count, rtt),
	}
}

func truncateRaw(b []byte) string {
	if len(b) <= rawLimit {
		return string(b)
	}
	return string(b[:rawLimit])
}

func clampFraction(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
