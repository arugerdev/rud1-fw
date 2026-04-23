package sysstat

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// bucketInterval is how often the background sampler takes a snapshot.
// One sample per minute, kept for up to an hour, gives us a 60-bucket
// rolling window — plenty of resolution for p50/p95 while keeping the
// ring buffer tiny.
const (
	bucketInterval = 60 * time.Second
	maxBuckets     = 60 // → 1 hour window
)

// sample is a single point captured by the background sampler.
//
// We only retain CPUUsage and LoadAvg1 because those are the two metrics
// the UI graphs as rolling percentiles; the rest of Stats (memory, disk,
// temperature) is either already a gauge or small enough that the
// instantaneous value from Snapshot() is sufficient.
type sample struct {
	cpu  float64
	load float64
	at   time.Time
}

// RingBuffer is a mutex-guarded circular buffer of samples. The zero
// value is not usable — always obtain one via newRingBuffer.
type RingBuffer struct {
	mu      sync.Mutex
	data    []sample
	size    int // max slots, == maxBuckets
	head    int // next write position
	filled  bool
}

func newRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		data: make([]sample, size),
		size: size,
	}
}

// Push appends a new sample, evicting the oldest if full.
func (r *RingBuffer) Push(s sample) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[r.head] = s
	r.head = (r.head + 1) % r.size
	if r.head == 0 {
		r.filled = true
	}
}

// snapshotSamples returns a stable slice copy of the current samples in
// insertion order. Callers must treat it as read-only; the underlying
// array is freshly allocated on every call.
func (r *RingBuffer) snapshotSamples() []sample {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []sample
	if r.filled {
		out = make([]sample, r.size)
		copy(out, r.data[r.head:])
		copy(out[r.size-r.head:], r.data[:r.head])
	} else {
		out = make([]sample, r.head)
		copy(out, r.data[:r.head])
	}
	return out
}

// PercentilesSnapshot is the payload shape returned by
// Collector.Percentiles and serialised under the `percentiles` field of
// /api/system/stats when the caller asks for it.
//
// WindowSize is the number of samples currently held; WindowMinutes is
// the wall-clock span between the oldest and newest sample (useful for
// the UI to label "12 min rolling p95" while the buffer is still
// warming up). Both fields are populated even when the percentile
// values are zero because of insufficient data so the client can draw
// an appropriate placeholder.
type PercentilesSnapshot struct {
	P50Cpu        float64 `json:"p50Cpu"`
	P95Cpu        float64 `json:"p95Cpu"`
	P50Load       float64 `json:"p50Load"`
	P95Load       float64 `json:"p95Load"`
	WindowSize    int     `json:"windowSize"`
	WindowMinutes int     `json:"windowMinutes"`
}

// percentile returns the p-th percentile (p in [0,1]) of a sorted slice
// using the linear-interpolation method (NIST R-7 / Excel PERCENTILE).
// sorted MUST already be ascending; callers pass a copy to avoid
// mutating shared state.
func percentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n == 1 {
		return sorted[0]
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[n-1]
	}
	rank := p * float64(n-1)
	lo := int(rank)
	hi := lo + 1
	if hi >= n {
		return sorted[n-1]
	}
	frac := rank - float64(lo)
	return sorted[lo] + frac*(sorted[hi]-sorted[lo])
}

// percentiles computes the full PercentilesSnapshot from the current
// ring contents. Returns zeroed percentile values (but a populated
// WindowSize) when fewer than 5 samples have been collected so the UI
// can distinguish "warming up" from "healthy at 0%".
func (r *RingBuffer) percentiles() PercentilesSnapshot {
	samples := r.snapshotSamples()
	n := len(samples)
	snap := PercentilesSnapshot{WindowSize: n}
	if n == 0 {
		return snap
	}
	// Even with too-few samples, report the span so the UI can draw a
	// warm-up progress indicator.
	oldest := samples[0].at
	newest := samples[n-1].at
	if !oldest.IsZero() && !newest.IsZero() {
		span := newest.Sub(oldest)
		snap.WindowMinutes = int(span.Round(time.Minute) / time.Minute)
	}
	if n < 5 {
		return snap
	}
	cpus := make([]float64, n)
	loads := make([]float64, n)
	for i, s := range samples {
		cpus[i] = s.cpu
		loads[i] = s.load
	}
	sort.Float64s(cpus)
	sort.Float64s(loads)
	snap.P50Cpu = percentile(cpus, 0.50)
	snap.P95Cpu = percentile(cpus, 0.95)
	snap.P50Load = percentile(loads, 0.50)
	snap.P95Load = percentile(loads, 0.95)
	return snap
}

// Percentiles returns the current rolling-window percentile snapshot.
// Safe to call from any goroutine; a nil Collector returns a zero
// snapshot so callers never need to guard the pointer.
func (c *Collector) Percentiles() PercentilesSnapshot {
	if c == nil || c.samples == nil {
		return PercentilesSnapshot{}
	}
	return c.samples.percentiles()
}

// Start launches the background sampler goroutine. It is idempotent —
// subsequent calls after the first successful start are no-ops — so
// callers don't need to coordinate. The goroutine exits when ctx is
// cancelled.
//
// The first sample is taken immediately so Percentiles() has something
// to report on cold start; subsequent samples follow bucketInterval.
func (c *Collector) Start(ctx context.Context) {
	if c == nil {
		return
	}
	c.startOnce.Do(func() {
		if c.samples == nil {
			c.samples = newRingBuffer(maxBuckets)
		}
		go c.sampleLoop(ctx)
	})
}

// sampleLoop is the background worker that pushes one sample per
// bucketInterval into the ring buffer. A slow Snapshot is bounded by a
// 5s timeout so a hung /proc read never skews the cadence; a failed
// snapshot is logged at debug and simply skipped.
func (c *Collector) sampleLoop(ctx context.Context) {
	take := func() {
		snapCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		s, err := c.Snapshot(snapCtx)
		if err != nil || s == nil {
			log.Debug().Err(err).Msg("sysstat: background sample failed")
			return
		}
		c.samples.Push(sample{
			cpu:  s.CPUUsage,
			load: s.LoadAvg1,
			at:   time.Now().UTC(),
		})
	}

	take()

	ticker := time.NewTicker(bucketInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			take()
		}
	}
}
