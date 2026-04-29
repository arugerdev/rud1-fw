package serbridge

import "time"

// Indirection over time.Sleep + time.Duration arithmetic so tests can
// pin pulse timing without sleeping for real. The production paths
// only ever go through these two helpers; the test build supplies
// fakes via build-tag overrides if/when we need them.

func pulseDuration(ms int) time.Duration { return time.Duration(ms) * time.Millisecond }

func sleepFor(d time.Duration) { time.Sleep(d) }
