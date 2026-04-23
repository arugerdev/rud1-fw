//go:build !linux

package sysstat

import (
	"context"
	"os"
)

// defaultRootPath uses the current working directory's volume on non-Linux
// hosts so the stats struct still reports something sensible for disk.
// The `populate` path always falls into the simulated branch so the value
// is decorative.
func defaultRootPath() string { return "/" }

// populate on non-Linux platforms always returns deterministic simulated
// values — the agent only ever runs in production on a Raspberry Pi.
func (c *Collector) populate(ctx context.Context, s *Stats) (*Stats, error) {
	_ = ctx
	hostname, _ := os.Hostname()
	s.Hostname = hostname
	return fillSimulated(s), nil
}
