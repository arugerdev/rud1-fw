// Cloud → agent config-patch ingestion (iter 48).
//
// Until iter 47 the cloud client was outbound-only: `HBConfigSnapshot`
// reported the agent's effective config, but a `DesiredConfigPatch`
// piggy-backed on the heartbeat *response* lets rud1-es push operator
// edits the other way without standing up a separate command channel.
//
// The applier here owns the patch-validate + atomic-save + side-effect
// (re-arm) sequence for every supported field. It deliberately reuses
// the existing config-validation constants (the same `[Min, Max]` window
// the local PUT handler enforces) and the same retentionPruner contract
// the iter-39 immediate-prune path uses, so a patch landing via the
// cloud is observationally identical to one landing via
// `PUT /api/system/audit/retention`.
//
// Safety contract:
//   - nil patch                                 → no-op, no save.
//   - patch with every field == current state   → no-op, no save.
//   - patch with any invalid field              → entire patch rejected,
//                                                 no save (an invalid
//                                                 cloud push must never
//                                                 corrupt local config).
//   - patch with at least one valid change      → cfg mutated in-place,
//                                                 cfg.Save() called once,
//                                                 per-field re-arm
//                                                 callbacks invoked AFTER
//                                                 a successful save.

package agent

import (
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/cloud"
)

// retentionPruner mirrors the contract the audit-retention HTTP handler
// uses (handlers.retentionPruner). Defined locally so the agent doesn't
// take a reach-around dependency on the handlers package — both
// implementations satisfy the same shape (configlog.DiskLogger has
// SetMaxFiles + PruneOld). Keeping it here lets tests stub the prune
// without spinning up a real disk logger.
type retentionPruner interface {
	SetMaxFiles(n int) int
	PruneOld() (int, error)
}

// configSaver abstracts the atomic config persistence path so tests
// can capture call counts and force errors without touching the real
// YAML on disk. The production implementation is `*config.Config`
// itself — `Save()` writes via temp-file + rename for crash safety.
type configSaver interface {
	Save() error
}

// desiredConfigApplier validates + applies a `DesiredConfigPatch` to
// the live config, then re-arms whichever runtime triggers the
// changed fields are wired to. Constructed once at agent boot and
// shared across heartbeat ticks; safe for sequential use (the
// heartbeat goroutine is single-threaded per tick).
//
// `pruner` is nil when the disk-backed audit logger failed to open
// (dev hardware / read-only fs) — the applier still updates the
// in-memory + persisted retention value but skips the prune side
// effect, mirroring the local PUT handler's degraded path.
type desiredConfigApplier struct {
	cfg    *config.Config
	saver  configSaver     // defaults to cfg itself; injectable for tests
	pruner retentionPruner // may be nil
}

// newDesiredConfigApplier wires the applier. Callers from agent.New
// pass the live cfg + the disk audit logger as pruner (or nil when
// unavailable). The saver path defaults to cfg.Save() so production
// callers don't have to think about it; tests inject a fake.
func newDesiredConfigApplier(cfg *config.Config, pruner retentionPruner) *desiredConfigApplier {
	return &desiredConfigApplier{cfg: cfg, saver: cfg, pruner: pruner}
}

// Apply ingests `patch` and returns (changed, err). `changed=true` is
// the signal that cfg.Save() ran AND at least one re-arm callback was
// invoked — useful for callers that want to log structured diff
// summaries. `err` is non-nil only when validation failed OR the save
// failed; in either case the in-memory cfg is rolled back so a partial
// failure can never leave the agent in a half-applied state.
//
// A nil patch, an all-fields-nil patch, or a patch whose fields all
// match current state returns (false, nil) without touching disk. This
// is the steady-state path on every heartbeat once the cloud has
// converged on the device's config — we explicitly do NOT rewrite the
// YAML on every heartbeat to avoid wearing out flash storage.
func (a *desiredConfigApplier) Apply(patch *cloud.DesiredConfigPatch) (bool, error) {
	if patch == nil {
		return false, nil
	}

	// ── Stage 1: pure validation + diff detection ───────────────────────
	// Validate every field FIRST so an invalid value in one field can't
	// commit the valid ones. The diff check also runs first so the
	// no-op-mutation path skips Save entirely.
	prevAuditRetention := a.cfg.System.AuditRetentionDays
	prevAuditEffective := a.cfg.System.AuditRetentionDaysOrDefault()

	type plannedChange struct {
		auditRetentionDays *int // non-nil ⇒ mutate to *auditRetentionDays
	}
	var plan plannedChange
	anyChange := false

	if patch.AuditRetentionDays != nil {
		v := *patch.AuditRetentionDays
		if v < config.MinAuditRetentionDays || v > config.MaxAuditRetentionDays {
			return false, fmt.Errorf(
				"auditRetentionDays=%d out of [%d,%d]",
				v, config.MinAuditRetentionDays, config.MaxAuditRetentionDays,
			)
		}
		// Compare against the configured value (NOT the post-clamp
		// effective value): a patch carrying the current configured
		// number is a no-op even if a previous run had clamped a
		// smuggled zero up to the default. This keeps the no-op
		// contract honest — same input ⇒ same output.
		if v != prevAuditRetention {
			plan.auditRetentionDays = &v
			anyChange = true
		}
	}

	if !anyChange {
		return false, nil
	}

	// ── Stage 2: mutate + persist atomically ────────────────────────────
	// Mutate in-memory first so cfg.Save() picks up the new values, then
	// roll back on persistence failure so a save error doesn't leave the
	// agent running with the new value but the old YAML on disk.
	if plan.auditRetentionDays != nil {
		a.cfg.System.AuditRetentionDays = *plan.auditRetentionDays
	}

	if err := a.saver.Save(); err != nil {
		// Roll back every staged mutation. Currently a single field, but
		// future patches may carry several — keeping the rollback
		// symmetric with the mutation stage means new fields just need
		// a matching restore line.
		if plan.auditRetentionDays != nil {
			a.cfg.System.AuditRetentionDays = prevAuditRetention
		}
		return false, fmt.Errorf("save desired config: %w", err)
	}

	// ── Stage 3: re-arm runtime triggers ────────────────────────────────
	// Only after a successful save — a re-arm before persistence would
	// leave the runtime out of sync with the YAML if Save() failed.
	if plan.auditRetentionDays != nil {
		newEffective := a.cfg.System.AuditRetentionDaysOrDefault()
		if a.pruner != nil {
			a.pruner.SetMaxFiles(newEffective)
			if newEffective < prevAuditEffective {
				if pruned, err := a.pruner.PruneOld(); err != nil {
					// Mirror the local PUT handler: prune failures are
					// best-effort and warn-logged, the persisted change
					// stands.
					log.Warn().
						Err(err).
						Int("oldDays", prevAuditEffective).
						Int("newDays", newEffective).
						Msg("desired-config: audit retention shrunk; immediate prune failed (non-fatal)")
				} else {
					log.Info().
						Int("oldDays", prevAuditEffective).
						Int("newDays", newEffective).
						Int("pruned", pruned).
						Msg("desired-config: audit retention shrunk; immediate prune ran")
				}
			}
		}
		log.Info().
			Int("oldDays", prevAuditEffective).
			Int("newDays", newEffective).
			Msg("desired-config: audit retention applied from cloud")
	}

	return true, nil
}
