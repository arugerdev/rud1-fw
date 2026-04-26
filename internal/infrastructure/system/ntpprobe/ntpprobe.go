// Package ntpprobe is a minimal SNTPv4 client used by the time-health
// subsystem to detect clocks that have drifted from real-world time.
//
// We deliberately keep this small and self-contained instead of pulling in
// `github.com/beevik/ntp`: the firmware only needs a one-shot "what's the
// server time minus my clock?" measurement under a tight per-server
// timeout, and the SNTPv4 wire format (RFC 4330) is a single 48-byte UDP
// packet. The dependency surface of beevik/ntp also brings in features
// (Kiss-of-Death handling, leap second flags, dispersion math) we never
// use here.
//
// Threat model: this is a passive read for diagnostics, not a clock
// synchronisation source. We do not adjust the system clock — that's
// systemd-timesyncd's job. A spoofed reply only affects the
// `clockSkewSeconds` figure surfaced in the heartbeat, which an operator
// uses as a signal alongside the existing `ntpSynchronized` flag from
// timedatectl.
package ntpprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// ntpEpochOffset is the difference between the NTP epoch (1900-01-01) and
// the Unix epoch (1970-01-01) in seconds. SNTP timestamps are seconds
// since 1900; we convert to/from time.Time using this constant.
const ntpEpochOffset = 2208988800

// DefaultPort is the standard NTP service port. Servers configured by
// callers as "host" (no port) are dialled against this default.
const DefaultPort = "123"

// packetSize is the wire size of the SNTPv4 header (RFC 4330 §4). We do
// not request authentication MAC fields, so the payload is exactly 48
// bytes.
const packetSize = 48

// Result is the outcome of a single successful query.
//
// ServerTime is the NTP server's notion of "now" at the moment it
// composed the reply (the Transmit Timestamp field). LocalTime is the
// agent's wall clock measured immediately before the request was sent
// AND after the reply was parsed; we average the two to remove most of
// the round-trip bias before subtracting. Skew is the signed difference
// (server − local), positive when the server is ahead of the agent.
type Result struct {
	Server     string
	ServerTime time.Time
	LocalTime  time.Time
	Skew       time.Duration
	RTT        time.Duration
}

// ErrNoServers is returned when the caller passes an empty server list to
// Query — distinct from a network error so callers can distinguish a
// disabled/misconfigured probe from a genuine reachability failure.
var ErrNoServers = errors.New("ntpprobe: no servers configured")

// Query sends a single SNTPv4 request to each server in order, returning
// on the first successful reply. Each per-server attempt is bounded by
// `perServer` (the caller is expected to pick a small value such as 2s
// to keep heartbeat budgets predictable). The outer ctx provides the
// overall cancellation envelope and can be tighter than perServer ×
// len(servers) — when ctx fires we stop trying further servers.
//
// The dialer can be overridden via Dial for tests (a UDP loopback echo
// server in particular). When nil we use net.Dialer with the per-server
// deadline.
func Query(ctx context.Context, servers []string, perServer time.Duration, dial DialFunc) (*Result, error) {
	if len(servers) == 0 {
		return nil, ErrNoServers
	}
	if dial == nil {
		dial = defaultDial
	}
	var lastErr error
	for _, server := range servers {
		if ctx.Err() != nil {
			if lastErr != nil {
				return nil, fmt.Errorf("ntpprobe: cancelled (last error: %w)", lastErr)
			}
			return nil, ctx.Err()
		}
		res, err := queryOne(ctx, server, perServer, dial)
		if err == nil {
			return res, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("ntpprobe: all servers failed (last: %w)", lastErr)
}

// DialFunc is the signature net.Dialer.DialContext satisfies; injectable
// so tests can swap in a UDP loopback server.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

func defaultDial(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{}
	return d.DialContext(ctx, network, address)
}

// queryOne performs a single send/receive cycle against `server`.
// Failures are wrapped with the server identity so a multi-server
// fallback chain can log which one failed.
func queryOne(ctx context.Context, server string, perServer time.Duration, dial DialFunc) (*Result, error) {
	address := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		address = net.JoinHostPort(server, DefaultPort)
	}

	subCtx, cancel := context.WithTimeout(ctx, perServer)
	defer cancel()

	conn, err := dial(subCtx, "udp", address)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", server, err)
	}
	defer conn.Close()

	deadline, ok := subCtx.Deadline()
	if !ok {
		deadline = time.Now().Add(perServer)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set deadline %s: %w", server, err)
	}

	// Build a minimal SNTP client request:
	//
	//   LI=0 (no warning), VN=4 (SNTPv4), Mode=3 (client) → 0x23.
	//
	// All other fields stay zero. Some servers echo our Transmit
	// Timestamp back as Originate Timestamp, but for a one-shot skew
	// reading we only need the server's Transmit Timestamp on the way
	// back, so the request body can stay all-zero past byte 0.
	req := make([]byte, packetSize)
	req[0] = 0x23

	sent := time.Now()
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("write %s: %w", server, err)
	}

	resp := make([]byte, packetSize)
	if _, err := conn.Read(resp); err != nil {
		return nil, fmt.Errorf("read %s: %w", server, err)
	}
	received := time.Now()

	mode := resp[0] & 0x07
	if mode != 4 {
		// SNTPv4 §5: a server reply uses Mode=4. Anything else is
		// either a malformed packet or a reflector — fail loudly.
		return nil, fmt.Errorf("unexpected mode %d from %s", mode, server)
	}
	stratum := resp[1]
	if stratum == 0 {
		// Stratum 0 carries a "Kiss-of-Death" code (RFC 4330 §8) —
		// the server is rejecting our query. Treating any KoD as
		// failure is overzealous but safe for a diagnostic probe;
		// we'd rather show "probe failed" than a misleading skew.
		return nil, fmt.Errorf("kiss-of-death from %s", server)
	}

	// Parse the Transmit Timestamp (bytes 40..47). It's a 64-bit
	// fixed-point seconds-since-1900 value: 32-bit integer seconds
	// followed by 32-bit fractional seconds.
	secs := binary.BigEndian.Uint32(resp[40:44])
	frac := binary.BigEndian.Uint32(resp[44:48])
	if secs == 0 && frac == 0 {
		return nil, fmt.Errorf("zero transmit timestamp from %s", server)
	}
	serverTime := ntpToTime(secs, frac)

	// Estimate the local time at the midpoint of the round trip so the
	// returned skew is closer to the true server-vs-agent delta. RTT is
	// `received - sent`; the midpoint is `sent + RTT/2`.
	//
	// Windows-flake floor (iter 51): on stock Windows boxes the wall-
	// clock resolution from successive `time.Now()` calls can collapse
	// a sub-microsecond loopback round-trip to 0. Downstream code
	// (handlers, UI freshness checks) treats `RTT==0` as "no probe
	// happened yet". Floor the measurement at 1 nanosecond — that's
	// physically meaningless but it preserves the "probe ran, just
	// fast" signal for callers.
	rtt := received.Sub(sent)
	if rtt <= 0 {
		rtt = time.Nanosecond
	}
	localMid := sent.Add(rtt / 2)
	skew := serverTime.Sub(localMid)

	return &Result{
		Server:     server,
		ServerTime: serverTime,
		LocalTime:  localMid,
		Skew:       skew,
		RTT:        rtt,
	}, nil
}

// ntpToTime converts an NTP 64-bit fixed-point timestamp to time.Time.
// Exposed for tests so they can hand-craft replies without re-deriving
// the conversion in every fixture.
func ntpToTime(secs, frac uint32) time.Time {
	// frac/2^32 of a second, converted to nanoseconds. We do the
	// multiplication in 128-bit-ish space (uint64 has plenty of room
	// because frac < 2^32 and 1e9 < 2^30).
	nsec := (uint64(frac) * 1_000_000_000) >> 32
	return time.Unix(int64(secs)-ntpEpochOffset, int64(nsec)).UTC()
}

// TimeToNTP is the inverse of ntpToTime. Used by the test UDP server to
// build synthetic replies; kept exported (not under _test.go) so other
// packages can reuse it for their own NTP fixture servers if needed.
func TimeToNTP(t time.Time) (secs, frac uint32) {
	unix := t.Unix()
	nsec := t.Nanosecond()
	secs = uint32(unix + ntpEpochOffset)
	frac = uint32((uint64(nsec) << 32) / 1_000_000_000)
	return secs, frac
}
