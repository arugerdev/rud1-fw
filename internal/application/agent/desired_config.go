// Cloud → agent config-patch ingestion (iter 48; iter 50 multi-field).
//
// Until iter 47 the cloud client was outbound-only: `HBConfigSnapshot`
// reported the agent's effective config, but a `DesiredConfigPatch`
// piggy-backed on the heartbeat *response* lets rud1-es push operator
// edits the other way without standing up a separate command channel.
//
// Iter 50 generalises the iter-48/49 single-field (auditRetentionDays)
// applier to handle the full operator-tunable surface. Each field gets
// its own validator + diff check + per-field re-arm callback + audit
// log Action key, all batched into a single atomic Save() per Apply()
// call — never one Save per field, otherwise a multi-field patch with
// one bad value would partial-persist before validation rejected it.
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
//                                                 a successful save, one
//                                                 audit-log entry per
//                                                 field actually changed.

package agent

import (
	"context"
	"fmt"
	"strings"
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

// MaxDesiredNTPProbeServers caps the server list the cloud can push,
// mirroring `handlers.MaxNTPProbeServers` (8) without taking a hard
// dep on the handlers package. A typo upstream that double-pastes a
// pool list must NOT silently truncate operator intent — the applier
// rejects the whole patch above this cap, exactly like the local PUT.
const MaxDesiredNTPProbeServers = 8

// MaxDesiredLANRoutes caps the route list the cloud can push (iter 51).
// 32 is comfortably above what a typical operator deployment needs (a
// handful of /24 subnets per site) but tight enough to flag a runaway
// loop pasting routes on every heartbeat as misconfiguration rather
// than valid intent. The applier rejects the whole patch above this
// cap — never silently truncates.
const MaxDesiredLANRoutes = 32

// NTPApplyHook is invoked after a successful Save() when at least one
// of the NTP-related fields changed. The applier passes the post-apply
// snapshot (enabled + the canonical server list AFTER normalize) so
// the hook can push to `SystemTimeHealthHandler.SetProbeOptions` AND
// reset the heartbeat throttle in a single closure — mirroring the
// `SetOnApply` wiring on the local PUT handler.
//
// `servers` is the post-normalize slice (caller-owned copy, safe to
// retain). `perServer` is the live cfg.System.ExternalNTPProbeTimeout
// — iter 50 doesn't expose it as a desired-config field yet, but the
// hook needs it so the renderer side can rebuild a full
// ExternalNTPProbeOptions struct without re-reading cfg.
type NTPApplyHook func(enabled bool, servers []string, perServer time.Duration)

// LANRouteValidator validates a single CIDR against the live device
// state (its WG /24 source subnet) and returns the canonical
// (post-`net.ParseCIDR`-string) form. Wired by agent.go to a closure
// capturing the `lan.Manager` so the applier itself stays free of the
// `infrastructure/lan` import. A nil validator means "the agent never
// wired the LAN subsystem" (early-boot / dev hardware) and the applier
// rejects any LANRoutes patch with a clear error rather than silently
// dropping it.
type LANRouteValidator func(cidr string) (string, error)

// LANApplyHook is invoked after a successful Save() when the LAN
// route list actually changed. The applier passes the post-normalize
// canonical slice (caller-owned copy, safe to retain) AND the live
// `cfg.LAN.Enabled` flag. The hook closure in agent.go is responsible
// for the enabled-aware reapply: when enabled, push the full set into
// `lan.Manager.Apply(...)`; when disabled, push an empty set so any
// previously-installed iptables rules are torn down. This mirrors the
// `LANHandler.reapplyLocked()` semantic so a cloud push and a local
// PUT produce byte-identical kernel state.
type LANApplyHook func(routes []string, enabled bool)

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
// /var/lib/rud1/audit). Successful applies are still made; the
// configlog entry is just suppressed (mirrors the local PUT handler's
// "no auditL ⇒ no Append" branch).
//
// `ntpHook` is nil when the time-health handler isn't wired (early
// boot / tests). When present and an NTP field actually changed the
// hook fires AFTER the Save + per-field audit-append; mirrors the
// local PUT's order so the heartbeat throttle reset always trails
// successful disk persistence.
//
// `now` is injectable so tests can pin the timestamp written into the
// `LastDesiredConfigAppliedAt` accessor without racing the wall clock.
// Production callers leave it nil and get `time.Now`.
type desiredConfigApplier struct {
	cfg      *config.Config
	saver    configSaver     // defaults to cfg itself; injectable for tests
	pruner   retentionPruner // may be nil
	auditLog auditAppender   // may be nil

	hookMu       sync.Mutex
	ntpHook      NTPApplyHook      // may be nil
	lanValidator LANRouteValidator // may be nil — patch rejected when nil
	lanHook      LANApplyHook      // may be nil

	now func() time.Time

	// lastAppliedAt is the wall-clock time of the most recent successful
	// Apply that mutated disk state. Surfaced via LastAppliedAt() and
	// piggy-backed on the next heartbeat snapshot so the cloud can
	// confirm convergence without inferring from drift. Guarded by mu
	// because the heartbeat goroutine reads it from a different code
	// path (buildHeartbeatConfig) than the applier writes it.
	//
	// lastAppliedFields is the iter-52 sibling: the canonical wire-name
	// list of every field that actually changed in the most recent
	// successful Apply (e.g. ["auditRetentionDays","externalNTPServers"]).
	// Reset to a fresh slice on every successful Apply (so a cloud push
	// touching only NTP doesn't keep an audit-retention entry from a
	// prior tick). Guarded by mu — read by the new
	// `GET /api/system/desired-config/last-applied` handler.
	mu                sync.Mutex
	lastAppliedAt     *time.Time
	lastAppliedFields []string
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

// SetNTPApplyHook registers the iter-50 callback the applier fires
// after a successful save when at least one NTP-related field
// (`ExternalNTPProbeEnabled`, `ExternalNTPServers`) actually changed.
// Wired post-construction in agent.go so the callback can capture the
// `SystemTimeHealthHandler` reference + the throttle-mu pair without
// the applier needing a hard import of the handlers package. Calling
// with nil clears the hook (used in tests).
func (a *desiredConfigApplier) SetNTPApplyHook(fn NTPApplyHook) {
	a.hookMu.Lock()
	a.ntpHook = fn
	a.hookMu.Unlock()
}

// SetLANRouteValidator wires the iter-51 per-route CIDR validator.
// Called once by agent.go with a closure that captures the
// `lan.Manager` so the applier can validate against the device's WG
// source subnet without importing `infrastructure/lan` directly.
// Passing nil clears the validator (used in tests + the early-boot
// degraded path where the LAN subsystem hasn't been wired yet).
func (a *desiredConfigApplier) SetLANRouteValidator(v LANRouteValidator) {
	a.hookMu.Lock()
	a.lanValidator = v
	a.hookMu.Unlock()
}

// SetLANApplyHook registers the iter-51 callback the applier fires
// after a successful save when the LAN route list actually changed.
// Wired post-construction in agent.go so the callback can capture the
// `lan.Manager` reference without the applier growing a hard dep on
// the handlers package. Passing nil clears the hook.
func (a *desiredConfigApplier) SetLANApplyHook(fn LANApplyHook) {
	a.hookMu.Lock()
	a.lanHook = fn
	a.hookMu.Unlock()
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

// LastAppliedFields returns a fresh copy of the canonical wire-name
// list of fields that mutated in the most recent successful Apply, or
// nil when no cloud apply has ever touched disk on this device.
// Returned by copy so the caller can append/sort without aliasing the
// applier's internal slice. Used by the iter-52 `GET
// /api/system/desired-config/last-applied` handler so the local panel
// can surface a "last cloud push converged at … (N fields)" chip on
// the device-detail page WITHOUT round-tripping through rud1-es.
func (a *desiredConfigApplier) LastAppliedFields() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastAppliedFields == nil {
		return nil
	}
	out := make([]string, len(a.lastAppliedFields))
	copy(out, a.lastAppliedFields)
	return out
}

// normalizeLANRoutes is the iter-51 sibling of normalizeNTPServers
// for the LAN.Routes field. Each entry runs through the
// caller-supplied validator (which captures the manager's source
// subnet — overlap with the WG /24 is rejected there). Validated
// entries are then deduped on the canonical CIDR form (case is
// already normalised by `net.ParseCIDR`'s String() output). Returns
// an error when the post-dedupe length exceeds MaxDesiredLANRoutes,
// when a single entry fails CIDR validation, or when the validator
// itself is nil (the caller must wire one before pushing LAN
// patches). A nil/empty input returns an empty slice (cleared list)
// — the caller treats empty as "tear down all live rules", same
// semantic the local PUT enforces with `routes: []`.
func normalizeLANRoutes(in []string, v LANRouteValidator) ([]string, error) {
	if v == nil {
		return nil, fmt.Errorf("lanRoutes patch received but no LAN validator wired")
	}
	if len(in) == 0 {
		// Distinguish nil from empty for the diff check: an empty-vs-empty
		// or empty-vs-nil comparison after this is a no-op.
		return []string{}, nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		canonical, err := v(s)
		if err != nil {
			return nil, fmt.Errorf("invalid route %q: %w", s, err)
		}
		key := canonical
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, canonical)
	}
	if len(out) > MaxDesiredLANRoutes {
		return nil, fmt.Errorf("at most %d LAN routes allowed (got %d)", MaxDesiredLANRoutes, len(out))
	}
	return out, nil
}

// normalizeNTPServers mirrors `handlers.normalizeServers` exactly but
// inlined so the applier doesn't import the handlers package (per the
// auditAppender comment above — keeping the agent package out of a
// dep on the HTTP layer it serves). Trims whitespace, drops empties,
// dedupes case-insensitively, returns an error when the post-dedupe
// length exceeds MaxDesiredNTPProbeServers. A nil/empty input returns
// nil (cleared list) — the caller treats empty == "probe disabled
// regardless of Enabled flag", same semantic the local PUT uses.
func normalizeNTPServers(in []string) ([]string, error) {
	if len(in) == 0 {
		// Distinguish nil from empty for the diff check: a nil-vs-nil
		// or empty-vs-empty comparison after this is a no-op.
		return []string{}, nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		key := strings.ToLower(s)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	if len(out) > MaxDesiredNTPProbeServers {
		return nil, fmt.Errorf("at most %d NTP servers allowed (got %d)", MaxDesiredNTPProbeServers, len(out))
	}
	return out, nil
}

// stringSlicesEqual is the non-allocating order-sensitive equality used
// by the diff check. The cloud is expected to send servers in the same
// canonical order the agent reports back via heartbeat, so a different
// permutation legitimately means "operator changed the priority order"
// and SHOULD trip the change path. Order-insensitive equality would
// silently swallow that intent.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
	prevNTPEnabled := a.cfg.System.ExternalNTPProbeEnabled
	prevNTPServers := append([]string(nil), a.cfg.System.ExternalNTPServers...)
	prevLANRoutes := append([]string(nil), a.cfg.LAN.Routes...)

	type plannedChange struct {
		auditRetentionDays *int      // non-nil ⇒ mutate to *auditRetentionDays
		ntpProbeEnabled    *bool     // non-nil ⇒ mutate to *ntpProbeEnabled
		ntpServers         *[]string // non-nil ⇒ mutate to *ntpServers (post-normalize)
		lanRoutes          *[]string // non-nil ⇒ mutate to *lanRoutes (post-normalize)
	}
	var plan plannedChange

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
		}
	}

	if patch.ExternalNTPProbeEnabled != nil {
		v := *patch.ExternalNTPProbeEnabled
		if v != prevNTPEnabled {
			plan.ntpProbeEnabled = &v
		}
	}

	if patch.ExternalNTPServers != nil {
		normalized, err := normalizeNTPServers(*patch.ExternalNTPServers)
		if err != nil {
			return false, fmt.Errorf("externalNTPServers: %w", err)
		}
		// Treat nil and empty interchangeably for the diff check —
		// either represents "no servers configured". prev may be nil
		// (default config) or an empty []string (cleared via local PUT).
		if !stringSlicesEqual(normalized, prevNTPServers) {
			plan.ntpServers = &normalized
		}
	}

	if patch.LANRoutes != nil {
		// Snapshot the validator under the hookMu so a SetLAN* call in
		// flight can't race the diff check. The validator is a pure
		// function once captured, so we drop the lock before invoking.
		a.hookMu.Lock()
		validator := a.lanValidator
		a.hookMu.Unlock()
		normalized, err := normalizeLANRoutes(*patch.LANRoutes, validator)
		if err != nil {
			return false, fmt.Errorf("lanRoutes: %w", err)
		}
		// Treat nil and empty interchangeably for the diff check —
		// either represents "no routes configured" / "tear down all".
		if !stringSlicesEqual(normalized, prevLANRoutes) {
			plan.lanRoutes = &normalized
		}
	}

	anyChange := plan.auditRetentionDays != nil ||
		plan.ntpProbeEnabled != nil ||
		plan.ntpServers != nil ||
		plan.lanRoutes != nil

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
	if plan.ntpProbeEnabled != nil {
		a.cfg.System.ExternalNTPProbeEnabled = *plan.ntpProbeEnabled
	}
	if plan.ntpServers != nil {
		a.cfg.System.ExternalNTPServers = *plan.ntpServers
	}
	if plan.lanRoutes != nil {
		a.cfg.LAN.Routes = *plan.lanRoutes
	}

	if err := a.saver.Save(); err != nil {
		// Roll back every staged mutation. The rollback is symmetric
		// with the mutation stage so new fields just need a matching
		// restore line.
		//
		// Critical: NO audit log entry on this path. The on-disk YAML
		// never changed, so emitting any `system.*.set` entry would lie
		// to operators reading the configlog page. We also do NOT
		// advance lastAppliedAt — the cloud must keep re-pushing until
		// a save succeeds.
		if plan.auditRetentionDays != nil {
			a.cfg.System.AuditRetentionDays = prevAuditRetention
		}
		if plan.ntpProbeEnabled != nil {
			a.cfg.System.ExternalNTPProbeEnabled = prevNTPEnabled
		}
		if plan.ntpServers != nil {
			a.cfg.System.ExternalNTPServers = prevNTPServers
		}
		if plan.lanRoutes != nil {
			a.cfg.LAN.Routes = prevLANRoutes
		}
		return false, fmt.Errorf("save desired config: %w", err)
	}

	// Save succeeded — record the apply time so the next heartbeat can
	// confirm convergence to the cloud. Done BEFORE the prune / hook
	// side effects because lastAppliedAt is about "did the cloud's
	// edit reach disk", not "did the side-effects run cleanly".
	//
	// Iter 52: also snapshot the canonical wire-name list of fields
	// that mutated this tick so the local panel can render a
	// "last cloud push converged at … (fields: auditRetentionDays,
	// externalNTPServers)" chip without re-deriving the diff from
	// the configlog stream. The list is cleared-and-rebuilt each
	// tick so a NTP-only push doesn't carry forward a prior
	// audit-retention field name. Names match the `cloud.DesiredConfigPatch`
	// JSON tags so a single normalisation contract spans firmware ↔
	// cloud.
	now := a.now()
	fields := make([]string, 0, 4)
	if plan.auditRetentionDays != nil {
		fields = append(fields, "auditRetentionDays")
	}
	if plan.ntpProbeEnabled != nil {
		fields = append(fields, "externalNTPProbeEnabled")
	}
	if plan.ntpServers != nil {
		fields = append(fields, "externalNTPServers")
	}
	if plan.lanRoutes != nil {
		fields = append(fields, "lanRoutes")
	}
	a.mu.Lock()
	a.lastAppliedAt = &now
	a.lastAppliedFields = fields
	a.mu.Unlock()

	// ── Stage 3: per-field audit-log entries ────────────────────────────
	// One Action key per field actually changed. Mirrors the local PUT
	// handlers' Actions exactly (`system.audit.retention.set`,
	// `system.ntpProbe.update`) — only the Actor differs ("cloud" vs
	// "operator") so the configlog page can disambiguate cloud-applied
	// edits from operator-applied ones. Append failures are warn-logged
	// but never propagated.
	if a.auditLog != nil {
		if plan.auditRetentionDays != nil {
			a.appendAudit(configlog.Entry{
				Action:   "system.audit.retention.set",
				Actor:    "cloud",
				Previous: map[string]any{"days": prevAuditRetention},
				Next:     map[string]any{"days": *plan.auditRetentionDays},
				OK:       true,
			})
		}
		if plan.ntpProbeEnabled != nil || plan.ntpServers != nil {
			// Group both NTP fields into a single audit entry mirroring
			// the iter-29 local PUT shape (one entry per request,
			// regardless of whether the operator flipped enabled,
			// servers, or both). Snapshot the post-mutation slice so
			// the configlog reader sees the canonical normalised list.
			postServers := append([]string(nil), a.cfg.System.ExternalNTPServers...)
			a.appendAudit(configlog.Entry{
				Action: "system.ntpProbe.update",
				Actor:  "cloud",
				Previous: map[string]any{
					"enabled": prevNTPEnabled,
					"servers": prevNTPServers,
				},
				Next: map[string]any{
					"enabled": a.cfg.System.ExternalNTPProbeEnabled,
					"servers": postServers,
				},
				OK: true,
			})
		}
		if plan.lanRoutes != nil {
			// Iter-51: one audit entry per LAN-routes mutation. Action
			// key mirrors the local `PUT /api/lan/routes` Action so the
			// configlog page can display cloud + local edits in the same
			// stream — only the Actor differs ("cloud" vs "operator").
			postRoutes := append([]string(nil), a.cfg.LAN.Routes...)
			a.appendAudit(configlog.Entry{
				Action: "system.lan.routes.set",
				Actor:  "cloud",
				Previous: map[string]any{
					"routes": prevLANRoutes,
				},
				Next: map[string]any{
					"routes": postRoutes,
				},
				OK: true,
			})
		}
	}

	// ── Stage 4: re-arm runtime triggers ────────────────────────────────
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

	if plan.ntpProbeEnabled != nil || plan.ntpServers != nil {
		a.hookMu.Lock()
		hook := a.ntpHook
		a.hookMu.Unlock()
		if hook != nil {
			// Hand the post-apply snapshot to the hook. The slice is a
			// fresh copy so the hook can retain it without aliasing
			// cfg.System.ExternalNTPServers.
			postServers := append([]string(nil), a.cfg.System.ExternalNTPServers...)
			hook(
				a.cfg.System.ExternalNTPProbeEnabled,
				postServers,
				a.cfg.System.ExternalNTPProbeTimeout,
			)
		}
		log.Info().
			Bool("enabled", a.cfg.System.ExternalNTPProbeEnabled).
			Int("servers", len(a.cfg.System.ExternalNTPServers)).
			Msg("desired-config: NTP probe applied from cloud")
	}

	if plan.lanRoutes != nil {
		a.hookMu.Lock()
		hook := a.lanHook
		a.hookMu.Unlock()
		if hook != nil {
			// Hand the post-apply snapshot + the live Enabled flag to the
			// hook. The hook closure in agent.go is responsible for the
			// enabled-aware reapply: when enabled, push the routes into
			// `lan.Manager.Apply(...)`; when disabled, push an empty list
			// so any previously-installed iptables rules are torn down.
			postRoutes := append([]string(nil), a.cfg.LAN.Routes...)
			hook(postRoutes, a.cfg.LAN.Enabled)
		}
		log.Info().
			Int("routes", len(a.cfg.LAN.Routes)).
			Bool("enabled", a.cfg.LAN.Enabled).
			Msg("desired-config: LAN routes applied from cloud")
	}

	return true, nil
}

// appendAudit is a thin wrapper that emits one configlog entry and
// warn-logs an append failure rather than propagating it. Centralised
// so each per-field audit emission in Apply() stays a single line.
// Skipped silently when auditLog is nil (dev-hardware degraded path).
func (a *desiredConfigApplier) appendAudit(e configlog.Entry) {
	if a.auditLog == nil {
		return
	}
	if err := a.auditLog.Append(context.Background(), e); err != nil {
		log.Warn().Err(err).Str("action", e.Action).Msg("desired-config: audit append failed (non-fatal)")
	}
}
