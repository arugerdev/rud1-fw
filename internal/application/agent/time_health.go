// Package agent — heartbeat-side throttling for the compact `timeHealth`
// block. The /api/system/time-health HTTP handler still serves the full
// response; this file is concerned only with the smaller subset that
// rides along inside the heartbeat payload, and the rules that decide
// when to include it.
//
// The block is included when:
//   - the fingerprint differs from the last one we sent (rising/falling
//     edge — warnings appeared/disappeared, NTP sync flipped, TZ source
//     flipped, etc.), OR
//   - more than an hour has elapsed since we last sent one (keepalive
//     so the cloud can detect a hung agent that's no longer emitting).
//
// On the very first heartbeat the cached `lastSent` is the zero time, so
// the keepalive condition fires unconditionally — the first beat after
// startup always carries a snapshot.
package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// timeHealthKeepaliveInterval is the maximum gap between two consecutive
// `timeHealth` blocks when nothing has changed. Picked at one hour so the
// cloud can flag a stuck/hung device within a tolerable window without
// bloating every-30s heartbeats with redundant TZ data.
const timeHealthKeepaliveInterval = time.Hour

// timeHealthSnapshot is the projection of handlers.TimeHealthResponse the
// throttle logic operates on. Keeping it as a pure data struct (no I/O)
// makes shouldEmitTimeHealth trivially testable.
type timeHealthSnapshot struct {
	Timezone        string
	TimezoneSource  string
	IsUTC           bool
	NTPSynchronized bool
	NTPEnabled      bool
	Warnings        []string
}

// fingerprintTimeHealth returns a stable hash-equivalent of the throttle
// inputs: any change here means "ship a new block". Warnings are sorted
// to canonicalise slice ordering — two snapshots with identical sets of
// warnings emitted in different orders MUST produce the same fingerprint.
func fingerprintTimeHealth(s timeHealthSnapshot) string {
	warnings := append([]string(nil), s.Warnings...)
	sort.Strings(warnings)
	return fmt.Sprintf("%v|%v|%v|%v|%s|%s",
		s.IsUTC,
		s.NTPEnabled,
		s.NTPSynchronized,
		s.TimezoneSource,
		s.Timezone,
		strings.Join(warnings, "\x00"),
	)
}

// shouldEmitTimeHealth is the pure throttle decision exposed for unit
// tests. It returns true when the snapshot must be included in the
// outgoing heartbeat payload.
//
// Cases (any one suffices):
//   - lastSent is the zero time → first heartbeat after startup, always
//     include so the cloud's banner reflects state immediately.
//   - currentFp differs from lastFp → state changed, ship the new view.
//   - now - lastSent ≥ keepalive interval → keepalive tick fires.
//
// The function is intentionally side-effect free: the caller updates
// lastSent + lastFp only after a successful heartbeat send, so a
// transient network/exec failure doesn't suppress the next attempt.
func shouldEmitTimeHealth(now, lastSent time.Time, lastFp, currentFp string) bool {
	if lastSent.IsZero() {
		return true
	}
	if currentFp != lastFp {
		return true
	}
	return now.Sub(lastSent) >= timeHealthKeepaliveInterval
}

// buildTimeHealthBlock takes a snapshot + the current throttle state and
// returns either the compact heartbeat block (when it should be emitted)
// or nil. It does NOT mutate throttle state — the caller does that after
// a successful send.
//
// `capturedAt` is passed in (not derived from time.Now() inside this
// function) so tests can pin it without monkey-patching the clock.
func buildTimeHealthBlock(
	snap timeHealthSnapshot,
	capturedAt time.Time,
	now, lastSent time.Time,
	lastFp string,
) (block *hbTimeHealthLite, fingerprint string, emit bool) {
	fp := fingerprintTimeHealth(snap)
	if !shouldEmitTimeHealth(now, lastSent, lastFp, fp) {
		return nil, fp, false
	}
	warnings := snap.Warnings
	if len(warnings) == 0 {
		warnings = nil // ensure JSON omitempty drops the field cleanly
	}
	return &hbTimeHealthLite{
		Timezone:        snap.Timezone,
		TimezoneSource:  snap.TimezoneSource,
		IsUTC:           snap.IsUTC,
		NTPSynchronized: snap.NTPSynchronized,
		NTPEnabled:      snap.NTPEnabled,
		Warnings:        warnings,
		CapturedAt:      capturedAt.UTC().Format(time.RFC3339),
	}, fp, true
}

// hbTimeHealthLite mirrors cloud.HBTimeHealth but lives here so the
// throttle layer doesn't need to import the cloud package — useful both
// for keeping the dependency graph clean and for keeping tests free of
// transport types. The agent's heartbeat builder converts this to the
// cloud type at the call site.
type hbTimeHealthLite struct {
	Timezone        string
	TimezoneSource  string
	IsUTC           bool
	NTPSynchronized bool
	NTPEnabled      bool
	Warnings        []string
	CapturedAt      string
}

// captureTimeHealth runs the in-process snapshot under a tight 1s
// context budget so a slow timedatectl/systemctl shell never blocks the
// heartbeat. On timeout/error we return ok=false and the caller skips
// the block (without updating the throttle state, so the next tick
// retries). This keeps the heartbeat send-first, telemetry-second.
//
// Wrapped here (rather than inlined into sendHeartbeat) so the body is
// reusable from tests that want to drive the same code path against a
// stubbed snapshotter.
func captureTimeHealth(ctx context.Context, snapshot func(context.Context) timeHealthSnapshot) (timeHealthSnapshot, bool) {
	subCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	type result struct {
		snap timeHealthSnapshot
	}
	ch := make(chan result, 1)
	go func() {
		ch <- result{snap: snapshot(subCtx)}
	}()
	select {
	case r := <-ch:
		return r.snap, true
	case <-subCtx.Done():
		return timeHealthSnapshot{}, false
	}
}
