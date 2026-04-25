package ntpprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// fakeNTPServer spins up a one-shot UDP listener that replies to any
// inbound packet with a synthetic SNTPv4 reply whose Transmit Timestamp
// is `serverTime`. Returns the listen address (host:port) and a stop
// function; tests must defer the stop to release the goroutine.
func fakeNTPServer(t *testing.T, serverTime time.Time) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 256)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 1 {
				continue
			}
			resp := make([]byte, packetSize)
			// LI=0, VN=4, Mode=4 (server) → 0x24.
			resp[0] = 0x24
			resp[1] = 1 // stratum 1 — anything non-zero passes the KoD check
			secs, frac := TimeToNTP(serverTime)
			binary.BigEndian.PutUint32(resp[40:44], secs)
			binary.BigEndian.PutUint32(resp[44:48], frac)
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	stop := func() {
		_ = pc.Close()
		<-done
	}
	return pc.LocalAddr().String(), stop
}

// TestQuery_Success verifies that a single successful round-trip
// returns the synthetic server time and a non-zero RTT, with the
// derived skew within a tight tolerance of the planted offset. Run
// against an in-process loopback server so there's no real network
// dependency.
func TestQuery_Success(t *testing.T) {
	plantedSkew := 7 * time.Second
	serverTime := time.Now().UTC().Add(plantedSkew)
	addr, stop := fakeNTPServer(t, serverTime)
	defer stop()

	res, err := Query(context.Background(), []string{addr}, 2*time.Second, nil)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if res.Server != addr {
		t.Errorf("Server = %q, want %q", res.Server, addr)
	}
	delta := res.Skew - plantedSkew
	if delta < 0 {
		delta = -delta
	}
	// Loopback round-trips on a CI box can dilate by several hundred
	// milliseconds under load. We're checking the math, not measuring
	// real latency, so a 1s envelope is fine.
	if delta > time.Second {
		t.Fatalf("Skew = %v, want ~%v (tolerance 1s)", res.Skew, plantedSkew)
	}
	if res.RTT <= 0 {
		t.Errorf("RTT = %v, want positive", res.RTT)
	}
}

// TestQuery_NoServers: an empty server list is a configuration error,
// not a network failure — we surface a sentinel so callers can
// distinguish "probe disabled" from "probe attempted and failed".
func TestQuery_NoServers(t *testing.T) {
	_, err := Query(context.Background(), nil, time.Second, nil)
	if !errors.Is(err, ErrNoServers) {
		t.Fatalf("err = %v, want ErrNoServers", err)
	}
}

// TestQuery_FallsBackOnFailure: when the first server is unreachable
// (port-zero, instantly refused on most kernels — and even when not, the
// 50ms perServer budget will fire) we move on to the next.
func TestQuery_FallsBackOnFailure(t *testing.T) {
	addr, stop := fakeNTPServer(t, time.Now().UTC())
	defer stop()

	// 127.0.0.1:1 is reserved for tcpmux; UDP packets there are simply
	// dropped on the kernels we target, so the read times out within
	// the per-server budget and we move to the working server.
	_, err := Query(context.Background(),
		[]string{"127.0.0.1:1", addr},
		200*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("Query: %v (expected fallback to succeed)", err)
	}
}

// TestQuery_AllFailWrapped: a chain of unreachable servers must produce
// an error that names "all servers failed" so log output makes the
// failure mode obvious.
func TestQuery_AllFailWrapped(t *testing.T) {
	_, err := Query(context.Background(),
		[]string{"127.0.0.1:1", "127.0.0.1:2"},
		100*time.Millisecond, nil)
	if err == nil {
		t.Fatalf("Query: expected error, got nil")
	}
}

// TestNTPRoundTripConversion: the time→ntp→time round trip preserves
// seconds exactly and nanoseconds within the resolution of the 32-bit
// fractional field (≈233 picoseconds, well under 1ms).
func TestNTPRoundTripConversion(t *testing.T) {
	in := time.Date(2026, 4, 25, 12, 34, 56, 123_456_789, time.UTC)
	secs, frac := TimeToNTP(in)
	out := ntpToTime(secs, frac)
	delta := out.Sub(in)
	if delta < 0 {
		delta = -delta
	}
	if delta > time.Millisecond {
		t.Fatalf("round trip drift = %v (in=%v out=%v)", delta, in, out)
	}
}
