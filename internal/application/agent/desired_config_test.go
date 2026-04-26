package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rud1-es/rud1-fw/internal/config"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/audit/configlog"
	"github.com/rud1-es/rud1-fw/internal/infrastructure/cloud"
)

// fakePruner is the desired_config test double for retentionPruner. It
// records every SetMaxFiles + PruneOld invocation so assertions can pin
// call counts AND argument values, and lets a test force PruneOld to
// error to exercise the "prune-fails-but-persist-wins" branch.
type fakePruner struct {
	setMaxCalls   atomic.Int32
	pruneCalls    atomic.Int32
	lastSetMax    atomic.Int32
	pruneErr      error
	prunedPerCall int
}

func (f *fakePruner) SetMaxFiles(n int) int {
	f.setMaxCalls.Add(1)
	prev := f.lastSetMax.Load()
	f.lastSetMax.Store(int32(n))
	return int(prev)
}

func (f *fakePruner) PruneOld() (int, error) {
	f.pruneCalls.Add(1)
	return f.prunedPerCall, f.pruneErr
}

// fakeSaver records save calls + lets a test force the persist path to
// fail so the rollback branch is exercised without needing a read-only
// temp dir.
type fakeSaver struct {
	calls atomic.Int32
	err   error
}

func (f *fakeSaver) Save() error {
	f.calls.Add(1)
	return f.err
}

// newApplierForTest builds an applier wired to fakes — no disk I/O.
// The cfg argument is the live config the applier mutates; tests
// inspect it after Apply() to assert in-memory state. Iter 49 grew
// the constructor with an audit-appender slot; this helper passes nil
// so the iter-48 tests stay byte-for-byte identical (they only assert
// cfg + saver + pruner outcomes — the audit-log path has its own
// dedicated tests below).
func newApplierForTest(cfg *config.Config, pruner retentionPruner, saver configSaver) *desiredConfigApplier {
	a := newDesiredConfigApplier(cfg, pruner, nil)
	if saver != nil {
		a.saver = saver
	}
	return a
}

// intPtr is a one-line helper for the AuditRetentionDays *int field —
// keeps the table-driven tests readable.
func intPtr(v int) *int { return &v }

// ── Decoder back-compat (heartbeat response without desiredConfig) ──────

// TestHeartbeatResponse_DecodesWithoutDesiredConfig pins the iter ≤47
// wire shape: a heartbeat response missing the `desiredConfig` field
// must still decode cleanly into the new struct, with DesiredConfig==nil.
// A regression here would force every cloud deployment to ship the
// patch field before agents could roll the new firmware — exactly the
// kind of coupling the iter-48 design avoids.
func TestHeartbeatResponse_DecodesWithoutDesiredConfig(t *testing.T) {
	body := `{"ok":true,"status":"claimed","deviceId":"dev-1","nextCheckInSeconds":30}`
	var resp cloud.HeartbeatResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.DesiredConfig != nil {
		t.Fatalf("DesiredConfig should be nil when omitted, got %+v", resp.DesiredConfig)
	}
	if !resp.OK || resp.DeviceID != "dev-1" {
		t.Fatalf("non-DesiredConfig fields lost: %+v", resp)
	}
}

// TestHeartbeatResponse_DecodesWithDesiredConfigAuditRetention pins the
// happy path: a cloud response carrying `desiredConfig.auditRetentionDays`
// must decode into a non-nil DesiredConfig with the integer value
// readable through the pointer.
func TestHeartbeatResponse_DecodesWithDesiredConfigAuditRetention(t *testing.T) {
	body := `{"ok":true,"status":"claimed","desiredConfig":{"auditRetentionDays":21}}`
	var resp cloud.HeartbeatResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.DesiredConfig == nil {
		t.Fatalf("DesiredConfig should be populated")
	}
	if resp.DesiredConfig.AuditRetentionDays == nil {
		t.Fatalf("AuditRetentionDays should be populated")
	}
	if got := *resp.DesiredConfig.AuditRetentionDays; got != 21 {
		t.Fatalf("AuditRetentionDays=%d, want 21", got)
	}
}

// TestHeartbeatResponse_DecodesWithUnknownFields is the forward-compat
// guarantee: a cloud running ahead of the firmware can ship new fields
// inside `desiredConfig` (or at top level) without breaking the agent.
// stdlib json.Unmarshal silently ignores unknowns by default — this
// test exists to prevent a future contributor from "tightening" the
// decoder with DisallowUnknownFields, which would silently break
// rolling-deploy compatibility.
func TestHeartbeatResponse_DecodesWithUnknownFields(t *testing.T) {
	body := `{
		"ok": true,
		"status": "claimed",
		"futureTopLevel": {"x": 1},
		"desiredConfig": {
			"auditRetentionDays": 7,
			"someFutureField": "ignored"
		}
	}`
	var resp cloud.HeartbeatResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode with unknown fields must succeed, got: %v", err)
	}
	if resp.DesiredConfig == nil || resp.DesiredConfig.AuditRetentionDays == nil {
		t.Fatalf("known fields must still populate even with unknowns: %+v", resp.DesiredConfig)
	}
	if *resp.DesiredConfig.AuditRetentionDays != 7 {
		t.Fatalf("AuditRetentionDays=%d, want 7", *resp.DesiredConfig.AuditRetentionDays)
	}
}

// ── Apply: nil + no-op paths ────────────────────────────────────────────

// TestApply_NilPatch is the trivial steady-state path — most heartbeats
// in production carry no patch and must not touch disk.
func TestApply_NilPatch(t *testing.T) {
	cfg := config.Default()
	saver := &fakeSaver{}
	pruner := &fakePruner{}
	a := newApplierForTest(cfg, pruner, saver)

	changed, err := a.Apply(nil)
	if err != nil {
		t.Fatalf("nil patch must not error: %v", err)
	}
	if changed {
		t.Fatalf("nil patch must not report changed")
	}
	if saver.calls.Load() != 0 {
		t.Fatalf("nil patch must not call Save (got %d calls)", saver.calls.Load())
	}
	if pruner.setMaxCalls.Load() != 0 || pruner.pruneCalls.Load() != 0 {
		t.Fatalf("nil patch must not touch the pruner")
	}
}

// TestApply_AllFieldsNil is the "patch present but empty" no-op path.
// A cloud bug that emits an empty desiredConfig object on every tick
// must not nibble flash storage with one Save per heartbeat.
func TestApply_AllFieldsNil(t *testing.T) {
	cfg := config.Default()
	saver := &fakeSaver{}
	pruner := &fakePruner{}
	a := newApplierForTest(cfg, pruner, saver)

	changed, err := a.Apply(&cloud.DesiredConfigPatch{})
	if err != nil {
		t.Fatalf("empty patch must not error: %v", err)
	}
	if changed {
		t.Fatalf("empty patch must not report changed")
	}
	if saver.calls.Load() != 0 {
		t.Fatalf("empty patch must not call Save")
	}
}

// TestApply_SameValue_NoOp covers the "cloud is just echoing current
// state" path. A naive implementation that always called Save() on
// every non-nil pointer would burn a YAML write every heartbeat once
// the cloud started shipping the field — this test pins the diff
// check that prevents that.
func TestApply_SameValue_NoOp(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	saver := &fakeSaver{}
	pruner := &fakePruner{}
	a := newApplierForTest(cfg, pruner, saver)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(14)}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("same-value apply must not error: %v", err)
	}
	if changed {
		t.Fatalf("same-value apply must not report changed")
	}
	if saver.calls.Load() != 0 {
		t.Fatalf("same-value apply must not Save (got %d calls)", saver.calls.Load())
	}
	if pruner.pruneCalls.Load() != 0 {
		t.Fatalf("same-value apply must not Prune (got %d calls)", pruner.pruneCalls.Load())
	}
}

// ── Apply: change paths ─────────────────────────────────────────────────

// TestApply_Shrink_TriggersImmediatePrune is the iter-48 headline test:
// a cloud-pushed retention shrink must persist via Save AND fire
// SetMaxFiles + PruneOld so out-of-window day-files vanish without
// waiting for the next natural rotation. Mirrors the iter-39 contract
// the local PUT handler enforces — a cloud push and a local PUT must
// be observationally identical.
func TestApply_Shrink_TriggersImmediatePrune(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	saver := &fakeSaver{}
	pruner := &fakePruner{prunedPerCall: 9}
	a := newApplierForTest(cfg, pruner, saver)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(3)}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !changed {
		t.Fatalf("apply must report changed on a shrink")
	}
	if got := cfg.System.AuditRetentionDays; got != 3 {
		t.Fatalf("cfg not mutated: got %d, want 3", got)
	}
	if saver.calls.Load() != 1 {
		t.Fatalf("Save calls=%d, want 1", saver.calls.Load())
	}
	if pruner.setMaxCalls.Load() != 1 {
		t.Fatalf("SetMaxFiles calls=%d, want 1", pruner.setMaxCalls.Load())
	}
	if pruner.pruneCalls.Load() != 1 {
		t.Fatalf("PruneOld calls=%d, want 1", pruner.pruneCalls.Load())
	}
	if got := pruner.lastSetMax.Load(); got != 3 {
		t.Fatalf("SetMaxFiles last arg=%d, want 3", got)
	}
}

// TestApply_Grow_NoPrune covers the symmetrical iter-39 contract on
// the cloud-push path: enlarging the retention window has no on-disk
// files to delete, so PruneOld must NOT run. SetMaxFiles still fires
// so future appends honour the new bound.
func TestApply_Grow_NoPrune(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 3
	saver := &fakeSaver{}
	pruner := &fakePruner{}
	a := newApplierForTest(cfg, pruner, saver)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(30)}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !changed {
		t.Fatalf("apply must report changed on a grow")
	}
	if cfg.System.AuditRetentionDays != 30 {
		t.Fatalf("cfg.System.AuditRetentionDays=%d, want 30", cfg.System.AuditRetentionDays)
	}
	if saver.calls.Load() != 1 {
		t.Fatalf("Save calls=%d, want 1", saver.calls.Load())
	}
	if pruner.setMaxCalls.Load() != 1 {
		t.Fatalf("SetMaxFiles calls=%d, want 1 (always re-arm on change)", pruner.setMaxCalls.Load())
	}
	if pruner.pruneCalls.Load() != 0 {
		t.Fatalf("PruneOld calls=%d, want 0 on grow", pruner.pruneCalls.Load())
	}
}

// ── Apply: validation rejection ─────────────────────────────────────────

// TestApply_NegativeRejected is the headline rejection case — an
// auditRetentionDays<MinAuditRetentionDays must be refused without
// any side effect. A cloud bug or malicious push must not be able to
// disable the audit log.
func TestApply_NegativeRejected(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	saver := &fakeSaver{}
	pruner := &fakePruner{}
	a := newApplierForTest(cfg, pruner, saver)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(-5)}
	changed, err := a.Apply(patch)
	if err == nil {
		t.Fatalf("negative retention must error, got nil")
	}
	if changed {
		t.Fatalf("rejected patch must not report changed")
	}
	if cfg.System.AuditRetentionDays != 14 {
		t.Fatalf("cfg mutated despite rejection: %d", cfg.System.AuditRetentionDays)
	}
	if saver.calls.Load() != 0 {
		t.Fatalf("rejected patch must not Save")
	}
	if pruner.setMaxCalls.Load() != 0 || pruner.pruneCalls.Load() != 0 {
		t.Fatalf("rejected patch must not touch the pruner")
	}
}

// TestApply_ZeroRejected pins the lower-bound rejection: zero is
// invalid input. The local PUT handler rejects it identically — the
// "0 = use default" semantic only applies to a freshly-loaded YAML,
// not to a programmatic mutation arriving from the cloud where a
// zero almost certainly indicates a bug rather than intent.
func TestApply_ZeroRejected(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	saver := &fakeSaver{}
	a := newApplierForTest(cfg, nil, saver)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(0)}
	_, err := a.Apply(patch)
	if err == nil {
		t.Fatalf("zero retention must error")
	}
	if cfg.System.AuditRetentionDays != 14 || saver.calls.Load() != 0 {
		t.Fatalf("rejected patch leaked state: cfg=%d, saves=%d",
			cfg.System.AuditRetentionDays, saver.calls.Load())
	}
}

// TestApply_OversizeRejected pins the upper-bound rejection at
// MaxAuditRetentionDays+1. Catches a future bump of MaxAuditRetentionDays
// that forgets to update the validator.
func TestApply_OversizeRejected(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	saver := &fakeSaver{}
	a := newApplierForTest(cfg, nil, saver)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(config.MaxAuditRetentionDays + 1)}
	_, err := a.Apply(patch)
	if err == nil {
		t.Fatalf("oversize retention must error")
	}
	if cfg.System.AuditRetentionDays != 14 || saver.calls.Load() != 0 {
		t.Fatalf("rejected patch leaked state")
	}
}

// ── Apply: persistence + rollback ───────────────────────────────────────

// TestApply_SaveError_RollsBackInMemory: a Save() failure (e.g. fs full,
// EPERM) must roll the in-memory cfg back to the pre-apply state so
// the runtime doesn't drift from the YAML on disk. The pruner must
// also stay untouched — re-arming after a failed save would point the
// disk logger at a retention window the YAML never accepted.
func TestApply_SaveError_RollsBackInMemory(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	saver := &fakeSaver{err: errors.New("fs full")}
	pruner := &fakePruner{}
	a := newApplierForTest(cfg, pruner, saver)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(3)}
	_, err := a.Apply(patch)
	if err == nil {
		t.Fatalf("save error must propagate")
	}
	if cfg.System.AuditRetentionDays != 14 {
		t.Fatalf("rollback failed: cfg.System.AuditRetentionDays=%d, want 14",
			cfg.System.AuditRetentionDays)
	}
	if saver.calls.Load() != 1 {
		t.Fatalf("save should have been attempted once, got %d", saver.calls.Load())
	}
	if pruner.setMaxCalls.Load() != 0 || pruner.pruneCalls.Load() != 0 {
		t.Fatalf("pruner must not be re-armed after save failure")
	}
}

// TestApply_PruneError_PersistStillWins mirrors the local PUT handler's
// "prune failure must not propagate" semantics. The persisted config
// stands; the prune error gets warn-logged but the apply call returns
// success so heartbeat bookkeeping continues.
func TestApply_PruneError_PersistStillWins(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	saver := &fakeSaver{}
	pruner := &fakePruner{pruneErr: errors.New("forced prune failure")}
	a := newApplierForTest(cfg, pruner, saver)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(3)}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("prune failure must not propagate: %v", err)
	}
	if !changed {
		t.Fatalf("changed=false but persistence succeeded")
	}
	if cfg.System.AuditRetentionDays != 3 {
		t.Fatalf("persist must win even when prune errors: cfg=%d",
			cfg.System.AuditRetentionDays)
	}
	if pruner.pruneCalls.Load() != 1 {
		t.Fatalf("prune should have been attempted, got %d calls", pruner.pruneCalls.Load())
	}
}

// TestApply_NilPruner_StillSaves covers the dev-hardware path where
// the disk audit logger failed to open at boot. The applier must
// still persist the cfg change — mirroring the local PUT handler's
// degraded mode where the GET stats are empty but the retention
// number itself still round-trips.
func TestApply_NilPruner_StillSaves(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	saver := &fakeSaver{}
	a := newApplierForTest(cfg, nil, saver)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(7)}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !changed || cfg.System.AuditRetentionDays != 7 || saver.calls.Load() != 1 {
		t.Fatalf("nil pruner must not block save: changed=%v cfg=%d saves=%d",
			changed, cfg.System.AuditRetentionDays, saver.calls.Load())
	}
}

// ── End-to-end: real Save() + mock cloud server ─────────────────────────

// TestApply_RealConfigSave_RoundTripsToDisk wires the applier against a
// real *config.Config (with a writable temp YAML path) so the atomic
// Save path is exercised end-to-end. A reload from disk must observe
// the new retention value — guarding against a future Save refactor
// that silently drops a field.
func TestApply_RealConfigSave_RoundTripsToDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("system:\n  audit_retention_days: 14\n"), 0o644); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	pruner := &fakePruner{}
	a := newDesiredConfigApplier(cfg, pruner, nil)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(21)}
	if _, err := a.Apply(patch); err != nil {
		t.Fatalf("apply: %v", err)
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.System.AuditRetentionDays; got != 21 {
		t.Fatalf("reloaded retention=%d, want 21", got)
	}
}

// TestHeartbeat_MockCloud_ReturnsDesiredConfig is the integration-level
// proof that the wire shape, the cloud client, and the patch decoder
// agree. A stdlib httptest server stands in for rud1-es and emits a
// minimal HBResponse JSON carrying a desiredConfig.auditRetentionDays
// field; the cloud.Client.Heartbeat call must surface it on the
// returned struct.
func TestHeartbeat_MockCloud_ReturnsDesiredConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"ok": true,
			"status": "claimed",
			"deviceId": "dev-1",
			"nextCheckInSeconds": 30,
			"desiredConfig": {"auditRetentionDays": 7}
		}`))
	}))
	t.Cleanup(srv.Close)

	c := cloud.New(srv.URL, "secret", 5*time.Second)
	resp, err := c.Heartbeat(context.Background(), cloud.HeartbeatPayload{
		RegistrationCode: "code",
	})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if resp.DesiredConfig == nil || resp.DesiredConfig.AuditRetentionDays == nil {
		t.Fatalf("DesiredConfig.AuditRetentionDays missing: %+v", resp.DesiredConfig)
	}
	if *resp.DesiredConfig.AuditRetentionDays != 7 {
		t.Fatalf("AuditRetentionDays=%d, want 7", *resp.DesiredConfig.AuditRetentionDays)
	}
}

// TestHeartbeat_MockCloud_BackCompatNoDesiredConfig exercises the
// rolling-deploy guarantee against the real cloud client: a server
// that doesn't ship desiredConfig at all (iter ≤47 cloud) must still
// produce a clean Heartbeat call with DesiredConfig==nil — the agent
// then no-ops the apply.
func TestHeartbeat_MockCloud_BackCompatNoDesiredConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"status":"claimed","deviceId":"dev-1","nextCheckInSeconds":30}`))
	}))
	t.Cleanup(srv.Close)

	c := cloud.New(srv.URL, "secret", 5*time.Second)
	resp, err := c.Heartbeat(context.Background(), cloud.HeartbeatPayload{RegistrationCode: "code"})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if resp.DesiredConfig != nil {
		t.Fatalf("DesiredConfig should be nil from iter ≤47 cloud, got %+v", resp.DesiredConfig)
	}
	// Hand the nil patch to the applier — must be a clean no-op.
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	saver := &fakeSaver{}
	a := newApplierForTest(cfg, &fakePruner{}, saver)
	changed, err := a.Apply(resp.DesiredConfig)
	if err != nil || changed || saver.calls.Load() != 0 {
		t.Fatalf("nil patch from back-compat cloud must no-op: changed=%v err=%v saves=%d",
			changed, err, saver.calls.Load())
	}
}

// ── iter 49: configlog audit-trail + LastAppliedAt convergence chip ────

// fakeAuditAppender captures every Append() so iter-49 tests can pin
// the exact configlog.Entry shape a cloud apply emits — same Action
// the local PUT writes, but Actor:"cloud" so the configlog page can
// disambiguate. Errors can be forced to exercise the warn-and-continue
// branch (an audit-append failure must NEVER propagate; the persisted
// retention change still stands).
type fakeAuditAppender struct {
	mu      sync.Mutex
	calls   int
	entries []configlog.Entry
	err     error
}

func (f *fakeAuditAppender) Append(_ context.Context, e configlog.Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.entries = append(f.entries, e)
	return f.err
}

func (f *fakeAuditAppender) snapshot() []configlog.Entry {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]configlog.Entry, len(f.entries))
	copy(out, f.entries)
	return out
}

// newApplierForTestWithAudit is the iter-49 sibling of newApplierForTest
// that wires an audit-appender + an injectable now() so the tests can
// pin both the configlog entry AND the LastAppliedAt timestamp without
// racing the wall clock.
func newApplierForTestWithAudit(
	cfg *config.Config,
	pruner retentionPruner,
	saver configSaver,
	appender auditAppender,
	now func() time.Time,
) *desiredConfigApplier {
	a := newDesiredConfigApplier(cfg, pruner, appender)
	if saver != nil {
		a.saver = saver
	}
	if now != nil {
		a.now = now
	}
	return a
}

// TestApply_SuccessfulApply_WritesAuditLogWithCloudActor is the iter-49
// headline: a successful cloud apply must emit a `system.audit.retention.set`
// configlog entry with Actor:"cloud" and the same Previous/Next map keys
// the local PUT handler writes. This is the operator-visible signal that
// disambiguates "rud1-es pushed this" from "an admin clicked Save".
func TestApply_SuccessfulApply_WritesAuditLogWithCloudActor(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	saver := &fakeSaver{}
	appender := &fakeAuditAppender{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, appender, nil)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(21)}
	if _, err := a.Apply(patch); err != nil {
		t.Fatalf("apply: %v", err)
	}

	entries := appender.snapshot()
	if len(entries) != 1 {
		t.Fatalf("audit append calls=%d, want 1", len(entries))
	}
	e := entries[0]
	if e.Action != "system.audit.retention.set" {
		t.Fatalf("Action=%q, want system.audit.retention.set (mirror local PUT)", e.Action)
	}
	if e.Actor != "cloud" {
		t.Fatalf("Actor=%q, want cloud (iter-49 disambiguation)", e.Actor)
	}
	if !e.OK {
		t.Fatalf("OK=false on success path")
	}
	prev, ok := e.Previous.(map[string]any)
	if !ok || prev["days"] != 14 {
		t.Fatalf("Previous: got %#v, want {days:14}", e.Previous)
	}
	next, ok := e.Next.(map[string]any)
	if !ok || next["days"] != 21 {
		t.Fatalf("Next: got %#v, want {days:21}", e.Next)
	}
}

// TestApply_NoOp_SkipsAuditLog pins the "don't audit no-ops" rule:
// a same-value patch must NOT spam the configlog page on every
// heartbeat once the cloud starts shipping the field. A naive
// implementation that audited every Apply would generate one entry
// per heartbeat-tick — operators would lose the actual mutations in
// the noise.
func TestApply_NoOp_SkipsAuditLog(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	appender := &fakeAuditAppender{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, &fakeSaver{}, appender, nil)

	// nil patch
	if _, err := a.Apply(nil); err != nil {
		t.Fatalf("nil patch: %v", err)
	}
	// empty patch
	if _, err := a.Apply(&cloud.DesiredConfigPatch{}); err != nil {
		t.Fatalf("empty patch: %v", err)
	}
	// same-value patch
	if _, err := a.Apply(&cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(14)}); err != nil {
		t.Fatalf("same-value patch: %v", err)
	}

	if got := appender.calls; got != 0 {
		t.Fatalf("no-op apply must not audit-log: got %d calls", got)
	}
	if a.LastAppliedAt() != nil {
		t.Fatalf("no-op apply must not advance LastAppliedAt: got %v", a.LastAppliedAt())
	}
}

// TestApply_ValidationReject_SkipsAuditLog: a rejected patch must not
// emit a configlog entry. The on-disk YAML never changed; an audit
// entry would lie to operators reading the page. Symmetric with the
// rollback semantics of save-failure.
func TestApply_ValidationReject_SkipsAuditLog(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	appender := &fakeAuditAppender{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, &fakeSaver{}, appender, nil)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(-5)}
	if _, err := a.Apply(patch); err == nil {
		t.Fatalf("rejected patch must error")
	}
	if got := appender.calls; got != 0 {
		t.Fatalf("rejected patch must not audit-log: got %d calls", got)
	}
	if a.LastAppliedAt() != nil {
		t.Fatalf("rejected patch must not advance LastAppliedAt")
	}
}

// TestApply_SaveError_SkipsAuditLog: the rollback path. A Save()
// failure rolls in-memory cfg back; the audit log must NOT carry an
// entry for the change that never persisted, otherwise the configlog
// page would show a "successful" cloud apply that the YAML on disk
// never accepted.
func TestApply_SaveError_SkipsAuditLog(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	saver := &fakeSaver{err: errors.New("fs full")}
	appender := &fakeAuditAppender{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, appender, nil)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(3)}
	if _, err := a.Apply(patch); err == nil {
		t.Fatalf("save error must propagate")
	}
	if got := appender.calls; got != 0 {
		t.Fatalf("save-failure rollback must not audit-log: got %d calls", got)
	}
	if a.LastAppliedAt() != nil {
		t.Fatalf("save-failure rollback must not advance LastAppliedAt")
	}
}

// TestApply_AppendError_PersistStillWins: an audit-append failure
// (e.g. fs full mid-write) must not propagate. The persisted config
// stands, the warn is logged, the apply returns success — same
// degraded semantics the local PUT handler uses.
func TestApply_AppendError_PersistStillWins(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	saver := &fakeSaver{}
	appender := &fakeAuditAppender{err: errors.New("audit fs full")}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, appender, nil)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(7)}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("audit-append failure must not propagate: %v", err)
	}
	if !changed {
		t.Fatalf("changed=false despite successful save")
	}
	if cfg.System.AuditRetentionDays != 7 {
		t.Fatalf("persist must win even when audit errors: cfg=%d", cfg.System.AuditRetentionDays)
	}
	if appender.calls != 1 {
		t.Fatalf("audit Append should have been attempted, got %d calls", appender.calls)
	}
	if a.LastAppliedAt() == nil {
		t.Fatalf("LastAppliedAt must advance even when audit append fails")
	}
}

// TestApply_NilAuditLog_StillSaves covers the dev-hardware path: no
// writable /var/lib/rud1/audit at boot ⇒ auditLog is nil ⇒ apply
// must still persist the cfg change AND advance LastAppliedAt. The
// audit-log entry just goes nowhere — exactly mirroring the local PUT
// handler's "no auditL ⇒ no Append" branch.
func TestApply_NilAuditLog_StillSaves(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	saver := &fakeSaver{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, nil, nil)

	patch := &cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(7)}
	if _, err := a.Apply(patch); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if cfg.System.AuditRetentionDays != 7 {
		t.Fatalf("nil auditLog must not block save: cfg=%d", cfg.System.AuditRetentionDays)
	}
	if a.LastAppliedAt() == nil {
		t.Fatalf("nil auditLog must not block LastAppliedAt advance")
	}
}

// TestApply_LastAppliedAt_AdvancesOnSuccess pins the timestamp-
// monotonicity contract: every successful apply MUST move the
// LastAppliedAt pointer forward, so the cloud can confirm convergence
// for each push it sends — not just the first one.
func TestApply_LastAppliedAt_AdvancesOnSuccess(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	saver := &fakeSaver{}
	appender := &fakeAuditAppender{}

	// Pinned clock so the test asserts on exact values, not "after now".
	t1 := time.Date(2026, 4, 26, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 4, 26, 10, 5, 0, 0, time.UTC)
	var calls int
	now := func() time.Time {
		calls++
		if calls == 1 {
			return t1
		}
		return t2
	}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, appender, now)

	if _, err := a.Apply(&cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(7)}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	got := a.LastAppliedAt()
	if got == nil || !got.Equal(t1) {
		t.Fatalf("after first apply LastAppliedAt=%v, want %v", got, t1)
	}

	if _, err := a.Apply(&cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(21)}); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	got = a.LastAppliedAt()
	if got == nil || !got.Equal(t2) {
		t.Fatalf("after second apply LastAppliedAt=%v, want %v", got, t2)
	}
}

// TestApply_LastAppliedAt_ReturnsCopy guards against an API surface
// gotcha: a caller mutating the returned *time.Time must NOT corrupt
// the applier's internal state. Without the value-copy in
// LastAppliedAt(), a heartbeat that .UTC()'d the pointer in place
// could shift the applier's bookkeeping.
func TestApply_LastAppliedAt_ReturnsCopy(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	pinned := time.Date(2026, 4, 26, 11, 0, 0, 0, time.UTC)
	a := newApplierForTestWithAudit(
		cfg, &fakePruner{}, &fakeSaver{}, &fakeAuditAppender{},
		func() time.Time { return pinned },
	)
	if _, err := a.Apply(&cloud.DesiredConfigPatch{AuditRetentionDays: intPtr(7)}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	first := a.LastAppliedAt()
	if first == nil {
		t.Fatalf("LastAppliedAt should be populated")
	}
	*first = first.Add(48 * time.Hour) // attempt to corrupt
	second := a.LastAppliedAt()
	if !second.Equal(pinned) {
		t.Fatalf("LastAppliedAt mutated by caller: got %v, want %v", second, pinned)
	}
}

// TestBuildHeartbeatConfig_LastDesiredConfigAppliedAt_RoundTrips wires
// a fake state source into buildHeartbeatConfig and asserts the
// timestamp lands on `HBConfigSnapshot.LastDesiredConfigAppliedAt` in
// UTC. The applier always stores `time.Now()` (locale-tagged); the
// snapshot must normalise to UTC so the cloud's parser sees a stable
// `Z` suffix in JSON.
func TestBuildHeartbeatConfig_LastDesiredConfigAppliedAt_RoundTrips(t *testing.T) {
	cfg := config.Default()
	pinned := time.Date(2026, 4, 26, 12, 30, 0, 0, time.FixedZone("CEST", 2*3600))
	src := stubDesiredState{at: &pinned}
	got := buildHeartbeatConfig(cfg, nil, src)
	if got.LastDesiredConfigAppliedAt == nil {
		t.Fatalf("LastDesiredConfigAppliedAt missing from snapshot")
	}
	if got.LastDesiredConfigAppliedAt.Location() != time.UTC {
		t.Fatalf("LastDesiredConfigAppliedAt not UTC: %v", got.LastDesiredConfigAppliedAt.Location())
	}
	if !got.LastDesiredConfigAppliedAt.Equal(pinned) {
		t.Fatalf("LastDesiredConfigAppliedAt=%v, want equal to %v", got.LastDesiredConfigAppliedAt, pinned)
	}
}

// TestBuildHeartbeatConfig_LastDesiredConfigAppliedAt_OmittedWhenNil:
// fresh device, no cloud apply has ever run, the field must omit so
// older cloud schemas still parse cleanly AND the cloud doesn't
// render a misleading "applied at epoch zero" chip.
func TestBuildHeartbeatConfig_LastDesiredConfigAppliedAt_OmittedWhenNil(t *testing.T) {
	cfg := config.Default()
	src := stubDesiredState{at: nil}
	got := buildHeartbeatConfig(cfg, nil, src)
	if got.LastDesiredConfigAppliedAt != nil {
		t.Fatalf("LastDesiredConfigAppliedAt should be nil before any apply, got %v",
			got.LastDesiredConfigAppliedAt)
	}
	// Wire-shape regression: a stray `lastDesiredConfigAppliedAt` key
	// in the JSON would force iter ≤48 cloud schemas to either ignore
	// it (fine) or misinterpret an empty/zero string as "applied at
	// epoch". Easier to keep it omitted.
	buf, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(buf), "lastDesiredConfigAppliedAt") {
		t.Fatalf("nil LastDesiredConfigAppliedAt leaked to wire: %s", buf)
	}
}

// stubDesiredState is the `desiredConfigStateSource` minimal stub for
// the buildHeartbeatConfig iter-49 tests. Avoids spinning up a full
// applier (which would in turn require config + saver + pruner).
type stubDesiredState struct {
	at *time.Time
}

func (s stubDesiredState) LastAppliedAt() *time.Time { return s.at }

// ── iter 50: multi-field desired-config (externalNTP fields) ───────────

// boolPtr / strSlicePtr keep the iter-50 table-driven tests readable.
func boolPtr(v bool) *bool                { return &v }
func strSlicePtr(v ...string) *[]string   { x := append([]string(nil), v...); return &x }

// fakeNTPHook captures the iter-50 NTPApplyHook payloads so tests can
// pin the callback runs against the exact post-apply snapshot the
// applier built.
type fakeNTPHook struct {
	mu           sync.Mutex
	calls        int
	lastEnabled  bool
	lastServers  []string
	lastPerSrv   time.Duration
}

func (h *fakeNTPHook) Hook() NTPApplyHook {
	return func(enabled bool, servers []string, perServer time.Duration) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.calls++
		h.lastEnabled = enabled
		h.lastServers = append([]string(nil), servers...)
		h.lastPerSrv = perServer
	}
}

func (h *fakeNTPHook) snapshot() (int, bool, []string, time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := append([]string(nil), h.lastServers...)
	return h.calls, h.lastEnabled, out, h.lastPerSrv
}

// TestHeartbeatResponse_DecodesNTPFields pins the wire shape: the cloud
// can ship `externalNTPProbeEnabled` and `externalNTPServers` inside
// the `desiredConfig` block. The decoder must surface them on the
// pointer-typed fields without disturbing the iter-48 retention field.
func TestHeartbeatResponse_DecodesNTPFields(t *testing.T) {
	body := `{
		"ok": true,
		"desiredConfig": {
			"auditRetentionDays": 21,
			"externalNTPProbeEnabled": true,
			"externalNTPServers": ["pool.ntp.org", "time.cloudflare.com"]
		}
	}`
	var resp cloud.HeartbeatResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.DesiredConfig == nil {
		t.Fatalf("DesiredConfig nil")
	}
	if resp.DesiredConfig.ExternalNTPProbeEnabled == nil || *resp.DesiredConfig.ExternalNTPProbeEnabled != true {
		t.Fatalf("ExternalNTPProbeEnabled missing or wrong: %+v",
			resp.DesiredConfig.ExternalNTPProbeEnabled)
	}
	if resp.DesiredConfig.ExternalNTPServers == nil ||
		len(*resp.DesiredConfig.ExternalNTPServers) != 2 ||
		(*resp.DesiredConfig.ExternalNTPServers)[0] != "pool.ntp.org" {
		t.Fatalf("ExternalNTPServers: %+v", resp.DesiredConfig.ExternalNTPServers)
	}
	if resp.DesiredConfig.AuditRetentionDays == nil || *resp.DesiredConfig.AuditRetentionDays != 21 {
		t.Fatalf("retention field disturbed: %+v", resp.DesiredConfig.AuditRetentionDays)
	}
}

// TestApply_NTPEnabled_FiresHook_Persists_Audits is the iter-50 happy
// path: a cloud push enabling the probe must persist via Save, fire
// the NTP apply hook with the post-snapshot values, and emit one
// `system.ntpProbe.update` audit entry with Actor:"cloud".
func TestApply_NTPEnabled_FiresHook_Persists_Audits(t *testing.T) {
	cfg := config.Default()
	cfg.System.ExternalNTPProbeEnabled = false
	cfg.System.ExternalNTPProbeTimeout = 3 * time.Second
	saver := &fakeSaver{}
	appender := &fakeAuditAppender{}
	hook := &fakeNTPHook{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, appender, nil)
	a.SetNTPApplyHook(hook.Hook())

	patch := &cloud.DesiredConfigPatch{ExternalNTPProbeEnabled: boolPtr(true)}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !changed {
		t.Fatalf("changed=false, want true")
	}
	if !cfg.System.ExternalNTPProbeEnabled {
		t.Fatalf("cfg not mutated")
	}
	if saver.calls.Load() != 1 {
		t.Fatalf("Save calls=%d, want 1", saver.calls.Load())
	}
	calls, gotEnabled, _, gotPerSrv := hook.snapshot()
	if calls != 1 {
		t.Fatalf("hook calls=%d, want 1", calls)
	}
	if !gotEnabled {
		t.Fatalf("hook saw enabled=%v, want true", gotEnabled)
	}
	if gotPerSrv != 3*time.Second {
		t.Fatalf("hook saw perServer=%v, want 3s (preserved from cfg)", gotPerSrv)
	}
	entries := appender.snapshot()
	if len(entries) != 1 {
		t.Fatalf("audit entries=%d, want 1", len(entries))
	}
	if entries[0].Action != "system.ntpProbe.update" {
		t.Fatalf("Action=%q, want system.ntpProbe.update", entries[0].Action)
	}
	if entries[0].Actor != "cloud" {
		t.Fatalf("Actor=%q, want cloud", entries[0].Actor)
	}
	if a.LastAppliedAt() == nil {
		t.Fatalf("LastAppliedAt should advance on NTP apply")
	}
}

// TestApply_NTPServers_NormalizeAndDedupe pins the iter-50 server-list
// validation: the applier trims, drops empties, dedupes case-insensitive,
// and writes the canonical list to disk. Mirrors `handlers.normalizeServers`
// — a cloud push and a local PUT must produce byte-identical YAML.
func TestApply_NTPServers_NormalizeAndDedupe(t *testing.T) {
	cfg := config.Default()
	cfg.System.ExternalNTPServers = nil
	saver := &fakeSaver{}
	hook := &fakeNTPHook{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	a.SetNTPApplyHook(hook.Hook())

	patch := &cloud.DesiredConfigPatch{
		ExternalNTPServers: strSlicePtr(
			"  pool.ntp.org  ", "", "POOL.ntp.org", "time.cloudflare.com",
		),
	}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !changed {
		t.Fatalf("changed=false")
	}
	want := []string{"pool.ntp.org", "time.cloudflare.com"}
	got := cfg.System.ExternalNTPServers
	if len(got) != len(want) {
		t.Fatalf("post-normalize len=%d, want %d (got %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("post-normalize[%d]=%q, want %q (got %v)", i, got[i], want[i], got)
		}
	}
	_, _, hookServers, _ := hook.snapshot()
	if len(hookServers) != len(want) || hookServers[0] != want[0] {
		t.Fatalf("hook saw servers=%v, want %v", hookServers, want)
	}
}

// TestApply_NTPServers_OverCapRejected pins the upper-bound rejection:
// more than MaxDesiredNTPProbeServers entries (after dedupe) must
// reject the whole patch. A cloud bug pasting the same list twice
// must NOT silently truncate operator intent.
func TestApply_NTPServers_OverCapRejected(t *testing.T) {
	cfg := config.Default()
	saver := &fakeSaver{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)

	too := make([]string, MaxDesiredNTPProbeServers+1)
	for i := range too {
		too[i] = fmt.Sprintf("ntp-%d.example", i)
	}
	patch := &cloud.DesiredConfigPatch{ExternalNTPServers: &too}
	_, err := a.Apply(patch)
	if err == nil {
		t.Fatalf("over-cap server list must error")
	}
	if saver.calls.Load() != 0 {
		t.Fatalf("rejected patch must not Save, got %d", saver.calls.Load())
	}
}

// TestApply_NTPMultiField_AtomicSingleSave is the headline iter-50
// invariant: a patch carrying BOTH NTP fields fires exactly ONE Save()
// — never one per field, otherwise a multi-field patch with a bad
// value would partial-persist before the validator rejected it. Also
// fires exactly ONE hook invocation with the joint post-apply snapshot.
func TestApply_NTPMultiField_AtomicSingleSave(t *testing.T) {
	cfg := config.Default()
	cfg.System.ExternalNTPProbeEnabled = false
	cfg.System.ExternalNTPServers = nil
	saver := &fakeSaver{}
	hook := &fakeNTPHook{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	a.SetNTPApplyHook(hook.Hook())

	patch := &cloud.DesiredConfigPatch{
		ExternalNTPProbeEnabled: boolPtr(true),
		ExternalNTPServers:      strSlicePtr("pool.ntp.org"),
	}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !changed {
		t.Fatalf("changed=false")
	}
	if saver.calls.Load() != 1 {
		t.Fatalf("multi-field patch must Save exactly once, got %d", saver.calls.Load())
	}
	calls, gotEnabled, gotServers, _ := hook.snapshot()
	if calls != 1 {
		t.Fatalf("multi-field patch must fire hook exactly once, got %d calls", calls)
	}
	if !gotEnabled || len(gotServers) != 1 {
		t.Fatalf("hook saw joint snapshot wrong: enabled=%v servers=%v", gotEnabled, gotServers)
	}
}

// TestApply_RetentionAndNTP_TwoAuditEntries: a patch touching both
// the retention field AND an NTP field must emit exactly ONE entry per
// field (not one combined entry, not three). One Save, one
// LastAppliedAt advance, two configlog entries — same as if the
// operator had done two sequential local PUTs.
func TestApply_RetentionAndNTP_TwoAuditEntries(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	cfg.System.ExternalNTPProbeEnabled = false
	saver := &fakeSaver{}
	appender := &fakeAuditAppender{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, appender, nil)

	patch := &cloud.DesiredConfigPatch{
		AuditRetentionDays:      intPtr(7),
		ExternalNTPProbeEnabled: boolPtr(true),
	}
	if _, err := a.Apply(patch); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if saver.calls.Load() != 1 {
		t.Fatalf("Save calls=%d, want 1", saver.calls.Load())
	}
	entries := appender.snapshot()
	if len(entries) != 2 {
		t.Fatalf("audit entries=%d, want 2 (one per field)", len(entries))
	}
	actions := map[string]bool{entries[0].Action: true, entries[1].Action: true}
	if !actions["system.audit.retention.set"] || !actions["system.ntpProbe.update"] {
		t.Fatalf("expected both Action keys, got %v", actions)
	}
	for _, e := range entries {
		if e.Actor != "cloud" {
			t.Fatalf("Actor=%q on entry %s, want cloud", e.Actor, e.Action)
		}
	}
}

// TestApply_NTP_SameValue_NoOp pins the steady-state path: once the
// cloud has converged on the NTP fields, every subsequent heartbeat
// carrying the same values must NOT touch disk and must NOT fire the
// re-arm hook (otherwise the heartbeat throttle would reset every
// tick — the local PUT semantic is identical).
func TestApply_NTP_SameValue_NoOp(t *testing.T) {
	cfg := config.Default()
	cfg.System.ExternalNTPProbeEnabled = true
	cfg.System.ExternalNTPServers = []string{"pool.ntp.org"}
	saver := &fakeSaver{}
	hook := &fakeNTPHook{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	a.SetNTPApplyHook(hook.Hook())

	patch := &cloud.DesiredConfigPatch{
		ExternalNTPProbeEnabled: boolPtr(true),
		ExternalNTPServers:      strSlicePtr("pool.ntp.org"),
	}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if changed {
		t.Fatalf("same-value apply must report changed=false")
	}
	if saver.calls.Load() != 0 {
		t.Fatalf("same-value apply must not Save, got %d", saver.calls.Load())
	}
	calls, _, _, _ := hook.snapshot()
	if calls != 0 {
		t.Fatalf("same-value apply must not fire hook, got %d calls", calls)
	}
}

// TestApply_NTPSaveError_RollsBack: a Save() failure with a multi-field
// NTP patch must roll BOTH fields back to their pre-apply values so
// the runtime doesn't drift from disk. The hook must NOT fire either.
func TestApply_NTPSaveError_RollsBack(t *testing.T) {
	cfg := config.Default()
	cfg.System.ExternalNTPProbeEnabled = false
	cfg.System.ExternalNTPServers = []string{"old.example"}
	saver := &fakeSaver{err: errors.New("fs full")}
	hook := &fakeNTPHook{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	a.SetNTPApplyHook(hook.Hook())

	patch := &cloud.DesiredConfigPatch{
		ExternalNTPProbeEnabled: boolPtr(true),
		ExternalNTPServers:      strSlicePtr("new.example"),
	}
	if _, err := a.Apply(patch); err == nil {
		t.Fatalf("save error must propagate")
	}
	if cfg.System.ExternalNTPProbeEnabled {
		t.Fatalf("enabled rolled forward despite save failure")
	}
	if len(cfg.System.ExternalNTPServers) != 1 || cfg.System.ExternalNTPServers[0] != "old.example" {
		t.Fatalf("servers rolled forward despite save failure: %v", cfg.System.ExternalNTPServers)
	}
	calls, _, _, _ := hook.snapshot()
	if calls != 0 {
		t.Fatalf("hook fired despite save failure, got %d calls", calls)
	}
}

// TestApply_NTPNoHook_StillSaves covers the "hook not yet wired"
// boot-window: if the agent hasn't registered the NTP hook yet (early
// bootstrap), the applier must still persist + audit-log without
// panicking. Mirrors the iter-49 nil-pruner contract.
func TestApply_NTPNoHook_StillSaves(t *testing.T) {
	cfg := config.Default()
	cfg.System.ExternalNTPProbeEnabled = false
	saver := &fakeSaver{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	// no SetNTPApplyHook call

	patch := &cloud.DesiredConfigPatch{ExternalNTPProbeEnabled: boolPtr(true)}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !changed || !cfg.System.ExternalNTPProbeEnabled || saver.calls.Load() != 1 {
		t.Fatalf("nil hook must not block save: changed=%v cfg=%v saves=%d",
			changed, cfg.System.ExternalNTPProbeEnabled, saver.calls.Load())
	}
}

// TestApply_NTPServers_EmptyClears pins the "explicit empty list
// clears" semantic. A cloud push of `externalNTPServers: []` must
// reach disk as an empty list AND fire the hook so the live
// time-health handler stops probing.
func TestApply_NTPServers_EmptyClears(t *testing.T) {
	cfg := config.Default()
	cfg.System.ExternalNTPServers = []string{"pool.ntp.org"}
	saver := &fakeSaver{}
	hook := &fakeNTPHook{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	a.SetNTPApplyHook(hook.Hook())

	empty := []string{}
	patch := &cloud.DesiredConfigPatch{ExternalNTPServers: &empty}
	if _, err := a.Apply(patch); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(cfg.System.ExternalNTPServers) != 0 {
		t.Fatalf("servers not cleared: %v", cfg.System.ExternalNTPServers)
	}
	calls, _, hookServers, _ := hook.snapshot()
	if calls != 1 {
		t.Fatalf("hook calls=%d, want 1 on clear", calls)
	}
	if len(hookServers) != 0 {
		t.Fatalf("hook saw non-empty servers on clear: %v", hookServers)
	}
}

// TestApply_NTP_OrderChange_TripsDiff: server-list order matters. The
// cloud sending a different permutation legitimately means "operator
// changed the priority order"; the diff check must trip on that path
// rather than treating it as a no-op.
func TestApply_NTP_OrderChange_TripsDiff(t *testing.T) {
	cfg := config.Default()
	cfg.System.ExternalNTPServers = []string{"a.example", "b.example"}
	saver := &fakeSaver{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)

	patch := &cloud.DesiredConfigPatch{
		ExternalNTPServers: strSlicePtr("b.example", "a.example"),
	}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !changed {
		t.Fatalf("order change must trip diff (changed=false)")
	}
	if cfg.System.ExternalNTPServers[0] != "b.example" {
		t.Fatalf("post-apply order wrong: %v", cfg.System.ExternalNTPServers)
	}
	if saver.calls.Load() != 1 {
		t.Fatalf("Save calls=%d, want 1", saver.calls.Load())
	}
}

// TestNormalizeNTPServers_Direct exercises the inlined normalize
// helper directly so each branch (trim, drop-empty, dedupe, over-cap
// reject) is pinned independent of the Apply() integration.
func TestNormalizeNTPServers_Direct(t *testing.T) {
	t.Run("nil_returns_empty", func(t *testing.T) {
		out, err := normalizeNTPServers(nil)
		if err != nil || len(out) != 0 {
			t.Fatalf("got (%v, %v)", out, err)
		}
	})
	t.Run("trims_drops_empties_dedupes", func(t *testing.T) {
		out, err := normalizeNTPServers([]string{" a ", "", "A", "b"})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(out) != 2 || out[0] != "a" || out[1] != "b" {
			t.Fatalf("got %v", out)
		}
	})
	t.Run("over_cap_errors", func(t *testing.T) {
		too := make([]string, MaxDesiredNTPProbeServers+1)
		for i := range too {
			too[i] = fmt.Sprintf("h%d.example", i)
		}
		_, err := normalizeNTPServers(too)
		if err == nil {
			t.Fatalf("over-cap must error")
		}
	})
}

// ── iter 51: LAN routes desired-config ─────────────────────────────────

// fakeLANHook captures iter-51 LANApplyHook payloads.
type fakeLANHook struct {
	mu          sync.Mutex
	calls       int
	lastRoutes  []string
	lastEnabled bool
}

func (h *fakeLANHook) Hook() LANApplyHook {
	return func(routes []string, enabled bool) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.calls++
		h.lastRoutes = append([]string(nil), routes...)
		h.lastEnabled = enabled
	}
}

func (h *fakeLANHook) snapshot() (int, []string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := append([]string(nil), h.lastRoutes...)
	return h.calls, out, h.lastEnabled
}

// passthroughLANValidator is the iter-51 test validator: trivially
// canonicalises by parsing the CIDR. Mirrors `lan.ValidateRoute`'s
// IP-only + non-/32 + canonical-form invariants without taking a hard
// dep on the lan package (the applier itself has no such dep).
func passthroughLANValidator(cidr string) (string, error) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return "", errors.New("empty subnet")
	}
	// Reject obvious junk so the "validator-rejected" test path has a
	// predictable failure shape.
	if !strings.Contains(cidr, "/") {
		return "", fmt.Errorf("missing /mask: %q", cidr)
	}
	return strings.ToLower(cidr), nil
}

// TestHeartbeatResponse_DecodesLANRoutes pins the iter-51 wire shape:
// the cloud can ship `lanRoutes` inside the `desiredConfig` block.
// Decoder must surface the pointer-typed field without disturbing the
// iter-48/50 fields.
func TestHeartbeatResponse_DecodesLANRoutes(t *testing.T) {
	body := `{
		"ok": true,
		"desiredConfig": {
			"auditRetentionDays": 21,
			"lanRoutes": ["192.168.1.0/24", "10.10.0.0/16"]
		}
	}`
	var resp cloud.HeartbeatResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.DesiredConfig == nil {
		t.Fatalf("DesiredConfig nil")
	}
	if resp.DesiredConfig.LANRoutes == nil ||
		len(*resp.DesiredConfig.LANRoutes) != 2 ||
		(*resp.DesiredConfig.LANRoutes)[0] != "192.168.1.0/24" {
		t.Fatalf("LANRoutes: %+v", resp.DesiredConfig.LANRoutes)
	}
	if resp.DesiredConfig.AuditRetentionDays == nil || *resp.DesiredConfig.AuditRetentionDays != 21 {
		t.Fatalf("retention disturbed: %+v", resp.DesiredConfig.AuditRetentionDays)
	}
}

// TestApply_LANRoutes_FiresHook_Persists_Audits is the iter-51 happy
// path: a cloud push must persist via Save, fire the LAN apply hook
// with the post-apply slice + enabled flag, and emit one
// `system.lan.routes.set` audit entry with Actor:"cloud".
func TestApply_LANRoutes_FiresHook_Persists_Audits(t *testing.T) {
	cfg := config.Default()
	cfg.LAN.Enabled = true
	cfg.LAN.Routes = nil
	saver := &fakeSaver{}
	appender := &fakeAuditAppender{}
	hook := &fakeLANHook{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, appender, nil)
	a.SetLANRouteValidator(passthroughLANValidator)
	a.SetLANApplyHook(hook.Hook())

	patch := &cloud.DesiredConfigPatch{
		LANRoutes: strSlicePtr("192.168.1.0/24", "10.10.0.0/16"),
	}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !changed {
		t.Fatalf("changed=false, want true")
	}
	if len(cfg.LAN.Routes) != 2 || cfg.LAN.Routes[0] != "192.168.1.0/24" {
		t.Fatalf("cfg.LAN.Routes not mutated: %v", cfg.LAN.Routes)
	}
	if saver.calls.Load() != 1 {
		t.Fatalf("Save calls=%d, want 1", saver.calls.Load())
	}
	calls, gotRoutes, gotEnabled := hook.snapshot()
	if calls != 1 {
		t.Fatalf("hook calls=%d, want 1", calls)
	}
	if !gotEnabled {
		t.Fatalf("hook saw enabled=%v, want true (cfg.LAN.Enabled=true)", gotEnabled)
	}
	if len(gotRoutes) != 2 || gotRoutes[0] != "192.168.1.0/24" {
		t.Fatalf("hook saw routes=%v, want canonical post-apply set", gotRoutes)
	}
	entries := appender.snapshot()
	if len(entries) != 1 {
		t.Fatalf("audit entries=%d, want 1", len(entries))
	}
	if entries[0].Action != "system.lan.routes.set" {
		t.Fatalf("Action=%q, want system.lan.routes.set", entries[0].Action)
	}
	if entries[0].Actor != "cloud" {
		t.Fatalf("Actor=%q, want cloud", entries[0].Actor)
	}
	if a.LastAppliedAt() == nil {
		t.Fatalf("LastAppliedAt should advance on LAN apply")
	}
}

// TestApply_LANRoutes_DisabledFlagPropagatesToHook: when cfg.LAN.Enabled
// is false, the apply hook STILL fires (the desired list persisted) but
// the hook receives enabled=false so the closure in agent.go pushes an
// empty list into the manager — same observable kernel state as the
// local PUT's `Enabled=false` branch.
func TestApply_LANRoutes_DisabledFlagPropagatesToHook(t *testing.T) {
	cfg := config.Default()
	cfg.LAN.Enabled = false
	cfg.LAN.Routes = nil
	saver := &fakeSaver{}
	hook := &fakeLANHook{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	a.SetLANRouteValidator(passthroughLANValidator)
	a.SetLANApplyHook(hook.Hook())

	patch := &cloud.DesiredConfigPatch{LANRoutes: strSlicePtr("192.168.1.0/24")}
	if _, err := a.Apply(patch); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(cfg.LAN.Routes) != 1 {
		t.Fatalf("cfg.LAN.Routes must persist regardless of Enabled: %v", cfg.LAN.Routes)
	}
	calls, _, gotEnabled := hook.snapshot()
	if calls != 1 {
		t.Fatalf("hook calls=%d, want 1 (must fire even when disabled)", calls)
	}
	if gotEnabled {
		t.Fatalf("hook saw enabled=true but cfg.LAN.Enabled=false")
	}
}

// TestApply_LANRoutes_NormalizeAndDedupe pins the iter-51 normalisation:
// trim whitespace, drop empties, dedupe on canonical form (lowercase
// here per the test validator), preserve order.
func TestApply_LANRoutes_NormalizeAndDedupe(t *testing.T) {
	cfg := config.Default()
	cfg.LAN.Enabled = true
	cfg.LAN.Routes = nil
	saver := &fakeSaver{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	a.SetLANRouteValidator(passthroughLANValidator)

	patch := &cloud.DesiredConfigPatch{
		LANRoutes: strSlicePtr(
			"  192.168.1.0/24  ", "", "192.168.1.0/24", "10.0.0.0/8",
		),
	}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !changed {
		t.Fatalf("changed=false")
	}
	want := []string{"192.168.1.0/24", "10.0.0.0/8"}
	got := cfg.LAN.Routes
	if len(got) != len(want) {
		t.Fatalf("post-normalize len=%d, want %d (got %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

// TestApply_LANRoutes_OverCapRejected pins the upper-bound rejection
// at MaxDesiredLANRoutes+1. A cloud push above the cap (after dedupe)
// must reject the whole patch — never silently truncate.
func TestApply_LANRoutes_OverCapRejected(t *testing.T) {
	cfg := config.Default()
	cfg.LAN.Enabled = true
	saver := &fakeSaver{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	a.SetLANRouteValidator(passthroughLANValidator)

	too := make([]string, MaxDesiredLANRoutes+1)
	for i := range too {
		too[i] = fmt.Sprintf("10.%d.0.0/24", i)
	}
	patch := &cloud.DesiredConfigPatch{LANRoutes: &too}
	_, err := a.Apply(patch)
	if err == nil {
		t.Fatalf("over-cap route list must error")
	}
	if saver.calls.Load() != 0 {
		t.Fatalf("rejected patch must not Save, got %d", saver.calls.Load())
	}
}

// TestApply_LANRoutes_ValidatorRejection: an invalid CIDR (validator
// returns error) must reject the whole patch, leak no state, and fire
// no hook.
func TestApply_LANRoutes_ValidatorRejection(t *testing.T) {
	cfg := config.Default()
	cfg.LAN.Enabled = true
	cfg.LAN.Routes = []string{"192.168.1.0/24"}
	saver := &fakeSaver{}
	hook := &fakeLANHook{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	a.SetLANRouteValidator(passthroughLANValidator)
	a.SetLANApplyHook(hook.Hook())

	patch := &cloud.DesiredConfigPatch{
		LANRoutes: strSlicePtr("192.168.1.0/24", "not-a-cidr"),
	}
	_, err := a.Apply(patch)
	if err == nil {
		t.Fatalf("validator rejection must error")
	}
	if len(cfg.LAN.Routes) != 1 || cfg.LAN.Routes[0] != "192.168.1.0/24" {
		t.Fatalf("cfg leaked despite rejection: %v", cfg.LAN.Routes)
	}
	if saver.calls.Load() != 0 {
		t.Fatalf("rejected patch must not Save")
	}
	calls, _, _ := hook.snapshot()
	if calls != 0 {
		t.Fatalf("rejected patch must not fire hook, got %d", calls)
	}
}

// TestApply_LANRoutes_NilValidatorRejected: a patch arriving before
// the validator is wired (early-boot) must error rather than silently
// drop. Operators get a clear "patch ignored" trail in cloud logs.
func TestApply_LANRoutes_NilValidatorRejected(t *testing.T) {
	cfg := config.Default()
	cfg.LAN.Enabled = true
	saver := &fakeSaver{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	// no SetLANRouteValidator call

	patch := &cloud.DesiredConfigPatch{LANRoutes: strSlicePtr("192.168.1.0/24")}
	_, err := a.Apply(patch)
	if err == nil {
		t.Fatalf("nil validator must reject LAN patches")
	}
	if saver.calls.Load() != 0 {
		t.Fatalf("rejected patch must not Save")
	}
}

// TestApply_LANRoutes_SameValue_NoOp: the cloud echoing the current
// route list must NOT touch disk and must NOT fire the hook. Steady-
// state convergence path.
func TestApply_LANRoutes_SameValue_NoOp(t *testing.T) {
	cfg := config.Default()
	cfg.LAN.Enabled = true
	cfg.LAN.Routes = []string{"192.168.1.0/24"}
	saver := &fakeSaver{}
	hook := &fakeLANHook{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	a.SetLANRouteValidator(passthroughLANValidator)
	a.SetLANApplyHook(hook.Hook())

	patch := &cloud.DesiredConfigPatch{LANRoutes: strSlicePtr("192.168.1.0/24")}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if changed {
		t.Fatalf("same-value apply must report changed=false")
	}
	if saver.calls.Load() != 0 {
		t.Fatalf("same-value apply must not Save")
	}
	calls, _, _ := hook.snapshot()
	if calls != 0 {
		t.Fatalf("same-value apply must not fire hook")
	}
}

// TestApply_LANRoutes_EmptyClears: an explicit empty list clears
// cfg.LAN.Routes AND fires the hook so any previously-installed
// iptables rules are torn down. Mirrors the local PUT's `routes:[]`
// semantics.
func TestApply_LANRoutes_EmptyClears(t *testing.T) {
	cfg := config.Default()
	cfg.LAN.Enabled = true
	cfg.LAN.Routes = []string{"192.168.1.0/24"}
	saver := &fakeSaver{}
	hook := &fakeLANHook{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	a.SetLANRouteValidator(passthroughLANValidator)
	a.SetLANApplyHook(hook.Hook())

	empty := []string{}
	patch := &cloud.DesiredConfigPatch{LANRoutes: &empty}
	if _, err := a.Apply(patch); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(cfg.LAN.Routes) != 0 {
		t.Fatalf("routes not cleared: %v", cfg.LAN.Routes)
	}
	calls, gotRoutes, _ := hook.snapshot()
	if calls != 1 {
		t.Fatalf("hook calls=%d, want 1 on clear", calls)
	}
	if len(gotRoutes) != 0 {
		t.Fatalf("hook saw non-empty routes on clear: %v", gotRoutes)
	}
}

// TestApply_LANRoutes_OrderChange_TripsDiff: route order matters
// (mirrors the iter-50 NTP-server semantic). A different permutation
// represents operator intent and must trip the diff check.
func TestApply_LANRoutes_OrderChange_TripsDiff(t *testing.T) {
	cfg := config.Default()
	cfg.LAN.Enabled = true
	cfg.LAN.Routes = []string{"192.168.1.0/24", "10.0.0.0/8"}
	saver := &fakeSaver{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	a.SetLANRouteValidator(passthroughLANValidator)

	patch := &cloud.DesiredConfigPatch{
		LANRoutes: strSlicePtr("10.0.0.0/8", "192.168.1.0/24"),
	}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !changed {
		t.Fatalf("order change must trip diff")
	}
	if cfg.LAN.Routes[0] != "10.0.0.0/8" {
		t.Fatalf("post-apply order wrong: %v", cfg.LAN.Routes)
	}
}

// TestApply_LANRoutes_SaveError_RollsBack: a Save() failure with a
// LAN-routes patch must roll cfg.LAN.Routes back to the pre-apply
// value AND not fire the hook.
func TestApply_LANRoutes_SaveError_RollsBack(t *testing.T) {
	cfg := config.Default()
	cfg.LAN.Enabled = true
	cfg.LAN.Routes = []string{"old.example/24"}
	saver := &fakeSaver{err: errors.New("fs full")}
	hook := &fakeLANHook{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	a.SetLANRouteValidator(passthroughLANValidator)
	a.SetLANApplyHook(hook.Hook())

	patch := &cloud.DesiredConfigPatch{LANRoutes: strSlicePtr("192.168.1.0/24")}
	if _, err := a.Apply(patch); err == nil {
		t.Fatalf("save error must propagate")
	}
	if len(cfg.LAN.Routes) != 1 || cfg.LAN.Routes[0] != "old.example/24" {
		t.Fatalf("rollback failed: %v", cfg.LAN.Routes)
	}
	calls, _, _ := hook.snapshot()
	if calls != 0 {
		t.Fatalf("hook fired despite save failure")
	}
}

// TestApply_RetentionAndLAN_TwoAuditEntries: a multi-field patch
// touching both retention AND LAN routes must Save once + emit one
// audit entry per field (mirrors iter-50's retention+NTP regression).
func TestApply_RetentionAndLAN_TwoAuditEntries(t *testing.T) {
	cfg := config.Default()
	cfg.System.AuditRetentionDays = 14
	cfg.LAN.Enabled = true
	cfg.LAN.Routes = nil
	saver := &fakeSaver{}
	appender := &fakeAuditAppender{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, appender, nil)
	a.SetLANRouteValidator(passthroughLANValidator)
	a.SetLANApplyHook((&fakeLANHook{}).Hook())

	patch := &cloud.DesiredConfigPatch{
		AuditRetentionDays: intPtr(7),
		LANRoutes:          strSlicePtr("192.168.1.0/24"),
	}
	if _, err := a.Apply(patch); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if saver.calls.Load() != 1 {
		t.Fatalf("Save calls=%d, want 1 (atomic multi-field)", saver.calls.Load())
	}
	entries := appender.snapshot()
	if len(entries) != 2 {
		t.Fatalf("audit entries=%d, want 2 (one per field)", len(entries))
	}
	actions := map[string]bool{entries[0].Action: true, entries[1].Action: true}
	if !actions["system.audit.retention.set"] || !actions["system.lan.routes.set"] {
		t.Fatalf("expected both Action keys, got %v", actions)
	}
}

// TestApply_LANNoHook_StillSaves: a LAN patch landing before the apply
// hook is wired (early-boot) must still persist + audit-log without
// panicking. Mirrors the iter-50 nil-NTP-hook contract.
func TestApply_LANNoHook_StillSaves(t *testing.T) {
	cfg := config.Default()
	cfg.LAN.Enabled = true
	cfg.LAN.Routes = nil
	saver := &fakeSaver{}
	a := newApplierForTestWithAudit(cfg, &fakePruner{}, saver, &fakeAuditAppender{}, nil)
	a.SetLANRouteValidator(passthroughLANValidator)
	// no SetLANApplyHook call

	patch := &cloud.DesiredConfigPatch{LANRoutes: strSlicePtr("192.168.1.0/24")}
	changed, err := a.Apply(patch)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !changed || len(cfg.LAN.Routes) != 1 || saver.calls.Load() != 1 {
		t.Fatalf("nil hook must not block save: changed=%v cfg=%v saves=%d",
			changed, cfg.LAN.Routes, saver.calls.Load())
	}
}

// TestNormalizeLANRoutes_Direct exercises the inlined normalize helper
// directly so each branch is pinned independent of Apply().
func TestNormalizeLANRoutes_Direct(t *testing.T) {
	t.Run("nil_validator_errors", func(t *testing.T) {
		_, err := normalizeLANRoutes([]string{"192.168.1.0/24"}, nil)
		if err == nil {
			t.Fatalf("nil validator must error")
		}
	})
	t.Run("nil_input_returns_empty", func(t *testing.T) {
		out, err := normalizeLANRoutes(nil, passthroughLANValidator)
		if err != nil || len(out) != 0 {
			t.Fatalf("got (%v, %v)", out, err)
		}
	})
	t.Run("trims_drops_empties_dedupes", func(t *testing.T) {
		out, err := normalizeLANRoutes([]string{
			" 192.168.1.0/24 ", "", "192.168.1.0/24", "10.0.0.0/8",
		}, passthroughLANValidator)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(out) != 2 || out[0] != "192.168.1.0/24" || out[1] != "10.0.0.0/8" {
			t.Fatalf("got %v", out)
		}
	})
	t.Run("over_cap_errors", func(t *testing.T) {
		too := make([]string, MaxDesiredLANRoutes+1)
		for i := range too {
			too[i] = fmt.Sprintf("10.%d.0.0/24", i)
		}
		_, err := normalizeLANRoutes(too, passthroughLANValidator)
		if err == nil {
			t.Fatalf("over-cap must error")
		}
	})
	t.Run("validator_error_propagates", func(t *testing.T) {
		_, err := normalizeLANRoutes([]string{"junk"}, passthroughLANValidator)
		if err == nil {
			t.Fatalf("validator error must propagate")
		}
	})
}
