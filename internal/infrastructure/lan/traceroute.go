package lan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/platform"
)

// TraceResult is the outcome of a GET /api/lan/traceroute call.
type TraceResult struct {
	Target    string      `json:"target"`
	Hops      []TraceHop  `json:"hops"`
	Raw       string      `json:"raw"`
	Simulated bool        `json:"simulated"`
}

// TraceHop is a single hop in the route. Host/RttMs are nullable so the JSON
// can distinguish "hop timed out" (all pointers nil) from "hop responded in
// 0.000 ms" — the traceroute tool itself draws this distinction with `* * *`.
type TraceHop struct {
	Index int      `json:"index"`
	Host  *string  `json:"host"`
	RttMs *float64 `json:"rttMs"`
}

// TraceOptions tunes a single traceroute run. Zero values fall back to defaults.
type TraceOptions struct {
	MaxHops int // -m N, defaults to 15 when <= 0
}

// DefaultTraceOptions returns the same settings used by the handler when the
// client doesn't pass any query params.
func DefaultTraceOptions() TraceOptions {
	return TraceOptions{MaxHops: 15}
}

// Tracer runs traceroute probes. Stateless; the struct exists so wiring in
// agent.go mirrors Prober and so future extensions (UDP probe selection,
// ICMP fallback, …) don't break the handler's construction signature.
type Tracer struct{}

// traceRawLimit bounds how many bytes of the command's output we echo back.
// 2KB fits ~25 typical hop lines while keeping the JSON cheap.
const traceRawLimit = 2048

// traceHopRegexp matches a single `traceroute -n` hop line. Groups:
//  1. hop index
//  2. host (IP) or empty when fully lost (`* * *`)
//  3. rtt in ms or empty when lost
//
// Example inputs:
//
//	 1  192.168.1.1  1.234 ms
//	 2  * * *
//	 3  10.0.0.1  4.567 ms  4.501 ms  4.600 ms
var traceHopRegexp = regexp.MustCompile(`^\s*(\d+)\s+(?:(\*\s*\*\s*\*)|([^\s]+)\s+([0-9.]+)\s*ms)`)

// Trace runs `traceroute -q 1 -w 2 -m <max> -n <target>` on POSIX and parses
// the output. On Windows / RUD1_SIMULATE=1 we synthesise a deterministic
// 3-hop chain derived from SHA256(target) — the same approach as
// simulatePing — so rud1-app's UI has something to render in dev.
func (t *Tracer) Trace(ctx context.Context, target string, opts TraceOptions) (*TraceResult, error) {
	if err := ValidateTarget(target); err != nil {
		return nil, err
	}
	target = strings.TrimSpace(target)

	maxHops := opts.MaxHops
	if maxHops <= 0 {
		maxHops = 15
	}

	if platform.SimulateHardware() {
		return simulateTrace(target), nil
	}

	cmd := exec.CommandContext(ctx, "traceroute",
		"-q", "1",
		"-w", "2",
		"-m", strconv.Itoa(maxHops),
		"-n", target)
	out, _ := cmd.CombinedOutput()

	hops := parseTraceOutput(string(out))
	return &TraceResult{
		Target:    target,
		Hops:      hops,
		Raw:       truncateTraceRaw(out),
		Simulated: false,
	}, nil
}

// parseTraceOutput walks the per-hop lines and emits TraceHop entries. The
// header line from traceroute (`traceroute to example.com ...`) is skipped
// because it doesn't match the hop regex.
func parseTraceOutput(text string) []TraceHop {
	hops := make([]TraceHop, 0, 16)
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		m := traceHopRegexp.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		idx, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		hop := TraceHop{Index: idx}
		if m[2] == "" {
			// matched host+rtt branch (groups 3 and 4)
			host := m[3]
			rttMs, perr := strconv.ParseFloat(m[4], 64)
			if perr == nil {
				hop.Host = &host
				hop.RttMs = &rttMs
			}
		}
		hops = append(hops, hop)
	}
	return hops
}

// simulateTrace produces 3 deterministic hops seeded by SHA256(target) so
// repeated calls from the same dev machine give stable output.
func simulateTrace(target string) *TraceResult {
	sum := sha256.Sum256([]byte(target))
	hops := make([]TraceHop, 3)
	for i := 0; i < 3; i++ {
		// Each hop pulls a 16-bit slice of the digest for its RTT and a
		// different byte for the synthetic host octet so they don't collide.
		rttBits := binary.BigEndian.Uint16(sum[i*2 : i*2+2])
		rtt := 2.0 + float64(rttBits%28000)/1000.0 // [2.0, 30.0] ms
		host := fmt.Sprintf("10.%d.%d.%d", sum[i*3]%255, sum[i*3+1]%255, sum[i*3+2]%255)
		hops[i] = TraceHop{Index: i + 1, Host: &host, RttMs: &rtt}
	}
	log.Debug().
		Str("target", target).
		Int("hops", len(hops)).
		Bool("simulated", true).
		Msg("lan: traceroute (simulated)")

	var rawBuilder strings.Builder
	fmt.Fprintf(&rawBuilder, "simulated=true target=%s\n", target)
	for _, h := range hops {
		fmt.Fprintf(&rawBuilder, "%2d  %s  %.3f ms\n", h.Index, *h.Host, *h.RttMs)
	}
	return &TraceResult{
		Target:    target,
		Hops:      hops,
		Raw:       rawBuilder.String(),
		Simulated: true,
	}
}

func truncateTraceRaw(b []byte) string {
	if len(b) <= traceRawLimit {
		return string(b)
	}
	return string(b[:traceRawLimit])
}
