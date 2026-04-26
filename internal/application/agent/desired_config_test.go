package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rud1-es/rud1-fw/internal/config"
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
// inspect it after Apply() to assert in-memory state.
func newApplierForTest(cfg *config.Config, pruner retentionPruner, saver configSaver) *desiredConfigApplier {
	a := newDesiredConfigApplier(cfg, pruner)
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
	a := newDesiredConfigApplier(cfg, pruner)

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
