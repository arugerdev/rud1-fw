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
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/audit/configlog"
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

// auditAppender is the sliver of `configlog.Logger` the applier needs
// to log a successful cloud-driven mutation into the same JSONL stream
// the local PUT handler writes to. Both `configlog.DiskLogger` and
// `configlog.LoggerNoop` satisfy it. Defined locally (not imported
// from handlers) so the agent package doesn't grow a circular dep on
// the HTTP layer it ultimately serves.
type auditAppender interface {
	Append(ctx context.Context, e configlog.Entry) error
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
//
// `auditLog` is nil on the same dev-hardware path (no writable
// /var/lib/rud1/audit). Successful apples are still made; the
// configlog entry is just suppressed (mirrors the local PUT handler's
// "no auditL ⇒ no Append" branch).
//
// `now` is injectable so tests can pin the timestamp written into the
// `LastDesiredConfigAppliedAt` accessor without racing the wall clock.
// Production callers leave it nil and get `time.Now`.
type desiredConfigApplier struct {
	cfg      *config.Config
	saver    configSaver     // defaults to cfg itself; injectable for tests
	pruner   retentionPruner // may be nil
	auditLog auditAppender   // may be nil

	now func() time.Time

	// lastAppliedAt is the wall-clock time of the most recent successful
	// Apply that mutated disk state. Surfaced via LastAppliedAt() and
	// piggy-backed on the next heartbeat snapshot so the cloud can
	// confirm convergence without inferring from drift. Guarded by mu
	// because the heartbeat goroutine reads it from a different code
	// path (buildHeartbeatConfig) than the applier writes it.
	mu            sync.Mutex
	lastAppliedAt *time.Time
}

// newDesiredConfigApplier wires the applier. Callers from agent.New
// pass the live cfg + the disk audit logger as pruner (or nil when
// unavailable) + the same disk audit logger as auditLog (so a
// cloud-applied retention edit lands in the same JSONL stream as a
// local PUT, just with `Actor: "cloud"`). The saver path defaults to
// cfg.Save() so production callers don't have to think about it;
// tests inject a fake.
func newDesiredConfigApplier(cfg *config.Config, pruner retentionPruner, auditLog auditAppender) *desiredConfigApplier {
	return &desiredConfigApplier{
		cfg:      cfg,
		saver:    cfg,
		pruner:   pruner,
		auditLog: auditLog,
		now:      time.Now,
	}
}

// LastAppliedAt returns a pointer to the wall-clock time of the most
// recent successful cloud apply, or nil when no cloud apply has ever
// mutated disk state on this device. Returned by value-copy so the
// caller can mutate the pointer freely without racing the applier's
// internal state. `buildHeartbeatConfig` uses this to populate the
// matching `HBConfigSnapshot.LastDesiredConfigAppliedAt` field.
func (a *desiredConfigApplier) LastAppliedAt() *time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastAppliedAt == nil {
		return nil
	}
	t := *a.lastAppliedAt
	return &t
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
		//
		// Critical: NO audit log entry on this path. The on-disk YAML
		// never changed, so emitting a `system.audit.retention.set`
		// entry would lie to operators reading the configlog page. We
		// also do NOT advance lastAppliedAt — the cloud must keep
		// re-pushing until a save succeeds.
		if plan.auditRetentionDays != nil {
			a.cfg.System.AuditRetentionDays = prevAuditRetention
		}
		return false, fmt.Errorf("save desired config: %w", err)
	}

	// Save succeeded — record the apply time so the next heartbeat can
	// confirm convergence to the cloud. Done BEFORE the prune side
	// effect because lastAppliedAt is about "did the cloud's edit reach
	// disk", not "did the prune run cleanly". Mirrors the local PUT
	// handler's choice to return 200 on prune failure.
	now := a.now()
	a.mu.Lock()
	a.lastAppliedAt = &now
	a.mu.Unlock()

	// Mirror the local PUT handler's audit-log shape exactly: same
	// Action, same Previous/Next map keys, only the Actor differs
	// ("cloud" instead of "operator") so the configlog page can
	// disambiguate cloud-applied edits from operator-applied ones.
	// Append failures are warn-logged but never propagated — matches
	// every other audit-emitting handler in the codebase.
	if a.auditLog != nil && plan.auditRetentionDays != nil {
		if err := a.auditLog.Append(context.Background(), configlog.Entry{
			Action:   "system.audit.retention.set",
			Actor:    "cloud",
			Previous: map[string]any{"days": prevAuditRetention},
			Next:     map[string]any{"days": *plan.auditRetentionDays},
			OK:       true,
		}); err != nil {
			log.Warn().Err(err).Msg("desired-config: audit append failed (non-fatal)")
		}
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
