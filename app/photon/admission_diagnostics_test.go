package main

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestDiagnoseAutoJoinAdoptionNotPending(t *testing.T) {
	dir := t.TempDir()
	verified, runtime, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", true)
	network, result, err := corestate.ReconcileManagedAuthority(
		verified.Network, verified.ManagedZone, verified.IdentityPrivateKey.Public().(ed25519.PublicKey), time.Unix(1000, 0),
	)
	if err != nil || !result.Adopted {
		t.Fatalf("pre-adopt: result=%+v err=%v", result, err)
	}
	verified.Network = network
	now := time.Unix(2000, 0)
	d := diagnoseAutoJoinAdmission(verified, runtime.Admission, now)
	if d.Pending {
		t.Fatalf("diagnosis should not be pending after adoption")
	}
	if d.Reason != inspect.AdmissionReasonAdopted && d.Reason != inspect.AdmissionReasonNotApplicable {
		t.Fatalf("reason = %s, want adopted or not_applicable", d.Reason)
	}
}

func TestDiagnoseAutoJoinMissingParentZone(t *testing.T) {
	dir := t.TempDir()
	verified, runtime, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", true)
	delete(verified.Network.Zones, verified.ManagedZone.Parent())
	now := time.Unix(1000, 0)
	d := diagnoseAutoJoinAdmission(verified, runtime.Admission, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonMissingParentZone {
		t.Fatalf("reason = %s, want %s", d.Reason, inspect.AdmissionReasonMissingParentZone)
	}
}

func TestDiagnoseAutoJoinMissingDelegation(t *testing.T) {
	dir := t.TempDir()
	verified, runtime, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", true)
	parent := verified.ManagedZone.Parent()
	parentState := verified.Network.Zones[parent]
	if parentState == nil {
		t.Fatalf("parent zone missing")
	}
	delete(parentState.Delegations, verified.ManagedZone)
	now := time.Unix(1000, 0)
	d := diagnoseAutoJoinAdmission(verified, runtime.Admission, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonMissingDelegation {
		t.Fatalf("reason = %s, want %s", d.Reason, inspect.AdmissionReasonMissingDelegation)
	}
}

func TestDiagnoseAutoJoinDelegationKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	verified, runtime, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", false)
	now := time.Unix(1000, 0)
	d := diagnoseAutoJoinAdmission(verified, runtime.Admission, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonDelegationKeyMismatch {
		t.Fatalf("reason = %s, want %s", d.Reason, inspect.AdmissionReasonDelegationKeyMismatch)
	}
}

func TestDiagnoseAutoJoinNoBootstrapSync(t *testing.T) {
	dir := t.TempDir()
	verified, runtime, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", true)
	now := time.Unix(1000, 0)
	d := diagnoseAutoJoinAdmission(verified, runtime.Admission, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonNoBootstrapSync && d.Reason != inspect.AdmissionReasonWaitingForAdoption {
		t.Fatalf("reason = %s, want %s or %s", d.Reason, inspect.AdmissionReasonNoBootstrapSync, inspect.AdmissionReasonWaitingForAdoption)
	}
}

func TestDiagnoseAutoJoinWaitingForAdoption(t *testing.T) {
	dir := t.TempDir()
	verified, runtime, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", true)
	now := time.Unix(1000, 0)
	runtime.Admission = &admissionState{
		Pending:               true,
		PendingSinceUnix:      now.Add(-1 * time.Hour).Unix(),
		LastBootstrapSyncUnix: now.Add(-5 * time.Minute).Unix(),
	}
	d := diagnoseAutoJoinAdmission(verified, runtime.Admission, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonWaitingForAdoption {
		t.Fatalf("reason = %s, want %s", d.Reason, inspect.AdmissionReasonWaitingForAdoption)
	}
}

func TestDiagnoseAutoJoinJoinRequestPresent(t *testing.T) {
	dir := t.TempDir()
	verified, runtime, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", true)
	now := time.Unix(1000, 0)
	d := diagnoseAutoJoinAdmission(verified, runtime.Admission, now)
	if d.JoinRequestB64 == "" {
		t.Fatalf("join_request should be present for pending state with key")
	}
	if !d.HasZonePrivateKey {
		t.Fatalf("has_zone_private_key should be true")
	}
}

func TestUpdateAdmissionOnPendingSetsTimestamp(t *testing.T) {
	dir := t.TempDir()
	verified, runtime, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", true)
	now := time.Unix(5000, 0)
	updateAdmissionOnPending(verified, runtime, now)
	if runtime.Admission == nil {
		t.Fatalf("admission state should be initialized")
	}
	if !runtime.Admission.Pending {
		t.Fatalf("should be pending")
	}
	if runtime.Admission.PendingSinceUnix != now.Unix() {
		t.Fatalf("pending_since = %d, want %d", runtime.Admission.PendingSinceUnix, now.Unix())
	}
	if runtime.Admission.PendingReason == "" {
		t.Fatalf("pending_reason should not be empty")
	}
}

func TestUpdateAdmissionOnPendingPreservesTimestamp(t *testing.T) {
	dir := t.TempDir()
	verified, runtime, _ := buildPendingAutoJoinOwners(t, dir, "node-b.catofes.", true)
	originalTime := time.Unix(3000, 0)
	runtime.Admission = &admissionState{
		Pending:          true,
		PendingSinceUnix: originalTime.Unix(),
	}
	updateAdmissionOnPending(verified, runtime, time.Unix(5000, 0))
	if runtime.Admission.PendingSinceUnix != originalTime.Unix() {
		t.Fatalf("pending_since = %d, want %d (should be preserved)", runtime.Admission.PendingSinceUnix, originalTime.Unix())
	}
}

func TestAdmissionStatePersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writeTestPrivateKey(t, dir, "identity")
	rootPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	config := defaultAppConfig()
	config.StatePath = filepath.Join(dir, "photon.db")
	config.ManagedZone = "node-b.catofes."
	config.Identity.KeyPath = keyPath
	config.TrustedRootPublicKey = rootPub
	config.Bootstrap = []syncConfigPeer{{ID: "catofes.", Addr: "127.0.0.1:33434"}}
	rt := &Runtime{Config: config, StatePath: config.StatePath, Clock: func() time.Time { return time.Unix(1000, 0) }}

	boltStore, startup, err := openLinuxDaemonState(rt)
	if err != nil {
		t.Fatalf("openLinuxDaemonState: %v", err)
	}
	view := startup.Common.ReadView()
	if !autoJoinPendingVerified(view.State) {
		t.Fatalf("state should start pending")
	}
	stateStore, err := newPersistedDaemonStateStore(startup.Common, startup.Runtime, boltStore)
	if err != nil {
		startup.Common.Close()
		_ = boltStore.Close()
		t.Fatalf("newPersistedDaemonStateStore: %v", err)
	}
	_, committed, err := stateStore.commitRuntimeIfRevision(uint64(view.Revision), func(runtime *linuxRuntimeState) {
		updateAdmissionOnPending(view.State, runtime, time.Unix(1000, 0))
	})
	if err != nil || !committed {
		t.Fatalf("commit admission runtime = committed %v err %v", committed, err)
	}
	stateStore.common.Close()
	if err := boltStore.Close(); err != nil {
		t.Fatalf("Close BoltStore: %v", err)
	}

	reopenedStore, reopened, err := openLinuxDaemonState(rt)
	if err != nil {
		t.Fatalf("openLinuxDaemonState(reopened): %v", err)
	}
	if reopened.Runtime.Admission == nil {
		t.Fatalf("admission state should persist across reload")
	}
	if !reopened.Runtime.Admission.Pending {
		t.Fatalf("admission should still be pending after reload")
	}
	if reopened.Runtime.Admission.PendingReason == "" {
		t.Fatalf("pending_reason should persist after reload")
	}
	reopened.Common.Close()
	if err := reopenedStore.Close(); err != nil {
		t.Fatalf("Close reopened BoltStore: %v", err)
	}
}
