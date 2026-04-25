package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/audit/configlog"
)

// fakeAuditStats lets us drive buildHeartbeatConfig with a deterministic
// Stats() result without writing to disk. nil-ness is handled separately
// by passing nil directly into buildHeartbeatConfig (no fake needed).
type fakeAuditStats struct {
	out configlog.Stats
	err error
}

func (f fakeAuditStats) Stats() (configlog.Stats, error) {
	return f.out, f.err
}

// TestBuildHeartbeatConfig_ReportsEffectiveRetention asserts the snapshot
// echoes the post-clamp value the audit logger actually uses, not the raw
// YAML field. A reader that compared a divergence warning against
// `cfg.System.AuditRetentionDays` (raw) would false-positive when an
// operator typed 9999 — Validate() clamps that to 365 in-place, but a
// freshly-loaded struct or a programmatic mutation might not have run
// Validate yet, so the snapshot must always go through the accessor.
func TestBuildHeartbeatConfig_ReportsEffectiveRetention(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 30
	got := buildHeartbeatConfig(cfg, nil)
	if got == nil {
		t.Fatal("snapshot must never be nil")
	}
	if got.AuditRetentionDays != 30 {
		t.Fatalf("AuditRetentionDays: got %d, want 30", got.AuditRetentionDays)
	}
}

// TestBuildHeartbeatConfig_ZeroFallsBackToDefault: a programmatic zero
// must be reported as the default (14) — this matches what the audit
// logger uses at runtime via AuditRetentionDaysOrDefault, so the cloud
// sees the same number it would observe by inspecting on-disk rotated
// files.
func TestBuildHeartbeatConfig_ZeroFallsBackToDefault(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 0
	got := buildHeartbeatConfig(cfg, nil)
	if got.AuditRetentionDays != config.DefaultAuditRetentionDays {
		t.Fatalf("zero retention should fall back to default %d, got %d",
			config.DefaultAuditRetentionDays, got.AuditRetentionDays)
	}
}

// TestBuildHeartbeatConfig_NegativeFallsBackToDefault: negative is the
// programmatic equivalent of "unset" once Validate has run, but we still
// guard against it here so a hand-crafted Config in tests / dev tools
// produces a sensible snapshot without a Validate() round-trip.
func TestBuildHeartbeatConfig_NegativeFallsBackToDefault(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = -5
	got := buildHeartbeatConfig(cfg, nil)
	if got.AuditRetentionDays != config.DefaultAuditRetentionDays {
		t.Fatalf("negative retention should fall back to default %d, got %d",
			config.DefaultAuditRetentionDays, got.AuditRetentionDays)
	}
}

// TestBuildHeartbeatConfig_OversizeClampedToMax pins the upper bound. An
// operator who typed 9999 in the YAML before Validate ran would otherwise
// have us ship a 9999 to the cloud (and the cloud would compare against
// org default and warn about a 9000+ day window the device does not
// actually retain).
func TestBuildHeartbeatConfig_OversizeClampedToMax(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 9999
	got := buildHeartbeatConfig(cfg, nil)
	if got.AuditRetentionDays != config.MaxAuditRetentionDays {
		t.Fatalf("oversize retention should clamp to max %d, got %d",
			config.MaxAuditRetentionDays, got.AuditRetentionDays)
	}
}

// TestBuildHeartbeatConfig_DefaultConstructor_ReportsDefault sanity-checks
// that a fresh Default() Config (the agent's startup baseline) yields the
// documented default retention. Future contributors who change
// DefaultAuditRetentionDays will see this fail and remember to update the
// cloud-side warning thresholds.
func TestBuildHeartbeatConfig_DefaultConstructor_ReportsDefault(t *testing.T) {
	cfg := config.Default()
	got := buildHeartbeatConfig(cfg, nil)
	if got.AuditRetentionDays != config.DefaultAuditRetentionDays {
		t.Fatalf("Default() retention: got %d, want %d",
			got.AuditRetentionDays, config.DefaultAuditRetentionDays)
	}
}

// TestBuildHeartbeatConfig_NilAuditLog_OmitsStats: passing a nil stats
// source must not panic and must keep AuditRetentionStats nil so the
// cloud preserves whatever it last saw (or suppresses the chip on the
// very first heartbeat).
func TestBuildHeartbeatConfig_NilAuditLog_OmitsStats(t *testing.T) {
	cfg := config.Default()
	got := buildHeartbeatConfig(cfg, nil)
	if got.AuditRetentionStats != nil {
		t.Fatalf("AuditRetentionStats: got %+v, want nil", got.AuditRetentionStats)
	}
}

// TestBuildHeartbeatConfig_StatsErrorOmitsStats: a transient Stats()
// error must degrade gracefully — the rest of the snapshot still ships
// (so the cloud keeps observing retention drift) but the inventory
// block is suppressed rather than zero-stamped.
func TestBuildHeartbeatConfig_StatsErrorOmitsStats(t *testing.T) {
	cfg := config.Default()
	src := fakeAuditStats{err: errors.New("eperm")}
	got := buildHeartbeatConfig(cfg, src)
	if got.AuditRetentionStats != nil {
		t.Fatalf("AuditRetentionStats on Stats() error: got %+v, want nil", got.AuditRetentionStats)
	}
	if got.AuditRetentionDays == 0 {
		t.Fatalf("retention days should still ship even on Stats() error")
	}
}

// TestBuildHeartbeatConfig_StatsForwardedAndFormatted asserts the wire
// shape: counts are passed through as-is, time fields format to RFC3339
// in UTC, and zero-valued time.Time stays as the empty string (omitted
// over the wire by the JSON tag).
func TestBuildHeartbeatConfig_StatsForwardedAndFormatted(t *testing.T) {
	cfg := config.Default()
	oldest := time.Date(2025, 4, 1, 12, 30, 45, 0, time.UTC)
	newest := time.Date(2025, 4, 25, 9, 15, 0, 0, time.UTC)
	prune := time.Date(2025, 4, 25, 0, 0, 0, 0, time.UTC)
	src := fakeAuditStats{out: configlog.Stats{
		TotalEntries:  1234,
		TotalBytes:    567890,
		FileCount:     7,
		OldestEntryAt: oldest,
		NewestEntryAt: newest,
		LastPruneAt:   prune,
	}}
	got := buildHeartbeatConfig(cfg, src)
	if got.AuditRetentionStats == nil {
		t.Fatal("AuditRetentionStats: got nil, want populated")
	}
	s := got.AuditRetentionStats
	if s.TotalEntries != 1234 || s.TotalBytes != 567890 || s.FileCount != 7 {
		t.Fatalf("count fields: %+v", s)
	}
	if s.OldestEntryAt != "2025-04-01T12:30:45Z" {
		t.Fatalf("OldestEntryAt: got %q, want RFC3339 UTC", s.OldestEntryAt)
	}
	if s.NewestEntryAt != "2025-04-25T09:15:00Z" {
		t.Fatalf("NewestEntryAt: got %q, want RFC3339 UTC", s.NewestEntryAt)
	}
	if s.LastPruneAt != "2025-04-25T00:00:00Z" {
		t.Fatalf("LastPruneAt: got %q, want RFC3339 UTC", s.LastPruneAt)
	}
}

// TestBuildHeartbeatConfig_ZeroTimesOmitted: a freshly-installed Pi has
// no oldest/newest/prune timestamps yet (zero-valued time.Time). They
// must marshal to "" so the wire JSON stays small AND the cloud keeps
// "unknown" semantics (instead of misinterpreting epoch zero).
func TestBuildHeartbeatConfig_ZeroTimesOmitted(t *testing.T) {
	cfg := config.Default()
	src := fakeAuditStats{out: configlog.Stats{
		TotalEntries: 0,
		TotalBytes:   0,
		FileCount:    0,
	}}
	got := buildHeartbeatConfig(cfg, src)
	if got.AuditRetentionStats == nil {
		t.Fatal("stats block missing")
	}
	s := got.AuditRetentionStats
	if s.OldestEntryAt != "" || s.NewestEntryAt != "" || s.LastPruneAt != "" {
		t.Fatalf("zero times should marshal as empty: %+v", s)
	}
}
