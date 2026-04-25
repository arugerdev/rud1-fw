package agent

import (
	"testing"

	"github.com/rud1-es/rud1-fw/internal/config"
)

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
	got := buildHeartbeatConfig(cfg)
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
	got := buildHeartbeatConfig(cfg)
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
	got := buildHeartbeatConfig(cfg)
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
	got := buildHeartbeatConfig(cfg)
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
	got := buildHeartbeatConfig(cfg)
	if got.AuditRetentionDays != config.DefaultAuditRetentionDays {
		t.Fatalf("Default() retention: got %d, want %d",
			got.AuditRetentionDays, config.DefaultAuditRetentionDays)
	}
}
