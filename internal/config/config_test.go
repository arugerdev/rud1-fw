package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestValidateClampsAuditRetentionDays asserts the [1, 365] clamp with
// the documented 0/negative -> default fallback. The validator is
// intentionally lenient: bad values are corrected rather than refused
// so an operator typo doesn't gate agent boot on a non-safety-critical
// knob.
func TestValidateClampsAuditRetentionDays(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"zero defaults to 14", 0, DefaultAuditRetentionDays},
		{"negative defaults to 14", -5, DefaultAuditRetentionDays},
		{"large negative defaults to 14", -10000, DefaultAuditRetentionDays},
		{"one stays one", 1, 1},
		{"thirty stays thirty", 30, 30},
		{"max stays max", MaxAuditRetentionDays, MaxAuditRetentionDays},
		{"over max clamps to max", 1000, MaxAuditRetentionDays},
		{"way over max clamps to max", 1_000_000, MaxAuditRetentionDays},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.System.AuditRetentionDays = tc.in
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if cfg.System.AuditRetentionDays != tc.want {
				t.Fatalf("AuditRetentionDays=%d, want %d", cfg.System.AuditRetentionDays, tc.want)
			}
		})
	}
}

// TestAuditRetentionDaysOrDefault mirrors the validator's logic for the
// boot-time accessor. It must produce the same value the validator
// would write back, so configlog gets a consistent number whether or
// not Validate has run.
func TestAuditRetentionDaysOrDefault(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{0, DefaultAuditRetentionDays},
		{-1, DefaultAuditRetentionDays},
		{1, 1},
		{14, 14},
		{MaxAuditRetentionDays, MaxAuditRetentionDays},
		{MaxAuditRetentionDays + 1, MaxAuditRetentionDays},
		{99999, MaxAuditRetentionDays},
	}
	for _, tc := range cases {
		got := SystemConfig{AuditRetentionDays: tc.in}.AuditRetentionDaysOrDefault()
		if got != tc.want {
			t.Fatalf("OrDefault(%d)=%d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestDefaultIncludesAuditRetention: the Default() constructor must
// pre-populate the field so a fresh install does not rely on a
// post-Load Validate pass to materialise sensible behaviour.
func TestDefaultIncludesAuditRetention(t *testing.T) {
	cfg := Default()
	if cfg.System.AuditRetentionDays != DefaultAuditRetentionDays {
		t.Fatalf("Default AuditRetentionDays=%d, want %d", cfg.System.AuditRetentionDays, DefaultAuditRetentionDays)
	}
}

// TestYAMLRoundTripPreservesAuditRetention writes a config out, reads
// it back, and asserts the retention field survives. This guards the
// YAML tag from accidental drift (forgetting to add the tag would let
// Validate's default silently overwrite a user-set 30 with 14 on the
// next reload).
func TestYAMLRoundTripPreservesAuditRetention(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	cfg := Default()
	cfg.Path = path
	cfg.System.AuditRetentionDays = 45
	// Cloud disabled keeps Validate happy without a base_url/secret.
	cfg.Cloud.Enabled = false

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.System.AuditRetentionDays != 45 {
		t.Fatalf("after round-trip AuditRetentionDays=%d, want 45", loaded.System.AuditRetentionDays)
	}
}

// TestYAMLRoundTripClampsOversizedRetention: a config file with a
// hand-edited 9999 must come back clamped to MaxAuditRetentionDays
// after Load (which calls Validate). This is the operator-typo path.
func TestYAMLRoundTripClampsOversizedRetention(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	body := []byte("server:\n  port: 7070\nsystem:\n  audit_retention_days: 9999\n")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.System.AuditRetentionDays != MaxAuditRetentionDays {
		t.Fatalf("after Load AuditRetentionDays=%d, want %d", loaded.System.AuditRetentionDays, MaxAuditRetentionDays)
	}
}

// TestYAMLRoundTripDefaultsZeroRetention: an explicit `0` in YAML must
// be promoted to the default by Validate, NOT preserved as 0 (which
// would later confuse configlog into using its own internal 14 fallback
// — same number, but two sources of truth).
func TestYAMLRoundTripDefaultsZeroRetention(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	body := []byte("server:\n  port: 7070\nsystem:\n  audit_retention_days: 0\n")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.System.AuditRetentionDays != DefaultAuditRetentionDays {
		t.Fatalf("after Load AuditRetentionDays=%d, want %d", loaded.System.AuditRetentionDays, DefaultAuditRetentionDays)
	}
}
