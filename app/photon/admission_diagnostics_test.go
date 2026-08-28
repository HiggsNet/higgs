package main

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func diagnoseTestAutoJoinAdmission(state *stateFile, now time.Time) inspect.AdmissionDiagnosis {
	if state == nil {
		return diagnoseAutoJoinAdmission(nil, nil, now)
	}
	return diagnoseAutoJoinAdmission(&corestate.VerifiedState{
		ManagedZone: state.ManagedZone, Network: state.Network, IdentityPrivateKey: state.ZonePrivateKey,
	}, state.Admission, now)
}

func TestDiagnoseAutoJoinAdoptionNotPending(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", true)
	network, result, err := corestate.ReconcileManagedAuthority(
		state.Network, state.ManagedZone, state.ZonePrivateKey.Public().(ed25519.PublicKey), time.Unix(1000, 0),
	)
	if err != nil || !result.Adopted {
		t.Fatalf("pre-adopt: result=%+v err=%v", result, err)
	}
	state.Network = network
	now := time.Unix(2000, 0)
	d := diagnoseTestAutoJoinAdmission(state, now)
	if d.Pending {
		t.Fatalf("diagnosis should not be pending after adoption")
	}
	if d.Reason != inspect.AdmissionReasonAdopted && d.Reason != inspect.AdmissionReasonNotApplicable {
		t.Fatalf("reason = %s, want adopted or not_applicable", d.Reason)
	}
}

func TestDiagnoseAutoJoinMissingParentZone(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", true)
	delete(state.Network.Zones, state.ManagedZone.Parent())
	now := time.Unix(1000, 0)
	d := diagnoseTestAutoJoinAdmission(state, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonMissingParentZone {
		t.Fatalf("reason = %s, want %s", d.Reason, inspect.AdmissionReasonMissingParentZone)
	}
}

func TestDiagnoseAutoJoinMissingDelegation(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", true)
	parent := state.ManagedZone.Parent()
	parentState := state.Network.Zones[parent]
	if parentState == nil {
		t.Fatalf("parent zone missing")
	}
	delete(parentState.Delegations, state.ManagedZone)
	now := time.Unix(1000, 0)
	d := diagnoseTestAutoJoinAdmission(state, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonMissingDelegation {
		t.Fatalf("reason = %s, want %s", d.Reason, inspect.AdmissionReasonMissingDelegation)
	}
}

func TestDiagnoseAutoJoinDelegationKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", false)
	now := time.Unix(1000, 0)
	d := diagnoseTestAutoJoinAdmission(state, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonDelegationKeyMismatch {
		t.Fatalf("reason = %s, want %s", d.Reason, inspect.AdmissionReasonDelegationKeyMismatch)
	}
}

func TestDiagnoseAutoJoinNoBootstrapSync(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", true)
	now := time.Unix(1000, 0)
	d := diagnoseTestAutoJoinAdmission(state, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonNoBootstrapSync && d.Reason != inspect.AdmissionReasonWaitingForAdoption {
		t.Fatalf("reason = %s, want %s or %s", d.Reason, inspect.AdmissionReasonNoBootstrapSync, inspect.AdmissionReasonWaitingForAdoption)
	}
}

func TestDiagnoseAutoJoinWaitingForAdoption(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", true)
	now := time.Unix(1000, 0)
	state.Admission = &admissionState{
		Pending:               true,
		PendingSinceUnix:      now.Add(-1 * time.Hour).Unix(),
		LastBootstrapSyncUnix: now.Add(-5 * time.Minute).Unix(),
	}
	d := diagnoseTestAutoJoinAdmission(state, now)
	if !d.Pending {
		t.Fatalf("diagnosis should be pending")
	}
	if d.Reason != inspect.AdmissionReasonWaitingForAdoption {
		t.Fatalf("reason = %s, want %s", d.Reason, inspect.AdmissionReasonWaitingForAdoption)
	}
}

func TestDiagnoseAutoJoinJoinRequestPresent(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", true)
	now := time.Unix(1000, 0)
	d := diagnoseTestAutoJoinAdmission(state, now)
	if d.JoinRequestB64 == "" {
		t.Fatalf("join_request should be present for pending state with key")
	}
	if !d.HasZonePrivateKey {
		t.Fatalf("has_zone_private_key should be true")
	}
}

func TestUpdateAdmissionOnPendingSetsTimestamp(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", true)
	now := time.Unix(5000, 0)
	runtime := linuxRuntimeStateFromLegacy(state)
	updateAdmissionOnPending(verifiedStateForTest(state), runtime, now)
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
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", true)
	originalTime := time.Unix(3000, 0)
	state.Admission = &admissionState{
		Pending:          true,
		PendingSinceUnix: originalTime.Unix(),
	}
	runtime := linuxRuntimeStateFromLegacy(state)
	updateAdmissionOnPending(verifiedStateForTest(state), runtime, time.Unix(5000, 0))
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

	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if !autoJoinPending(state) {
		t.Fatalf("state should start pending")
	}

	runtime := linuxRuntimeStateFromLegacy(state)
	updateAdmissionOnPending(verifiedStateForTest(state), runtime, time.Unix(1000, 0))
	state.Admission = cloneAdmissionState(runtime.Admission)
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	reloaded, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(reloaded): %v", err)
	}
	if reloaded.Admission == nil {
		t.Fatalf("admission state should persist across reload")
	}
	if !reloaded.Admission.Pending {
		t.Fatalf("admission should still be pending after reload")
	}
	if reloaded.Admission.PendingReason == "" {
		t.Fatalf("pending_reason should persist after reload")
	}
}
