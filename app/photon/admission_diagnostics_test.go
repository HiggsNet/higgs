package main

import (
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Catofes/photon/internal/inspect"
)

func TestDiagnoseAutoJoinAdoptionNotPending(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", true)
	adopted, err := tryAdoptAutoJoinDelegation(state, time.Unix(1000, 0))
	if err != nil || !adopted {
		t.Fatalf("pre-adopt: adopted=%v err=%v", adopted, err)
	}
	now := time.Unix(2000, 0)
	d := diagnoseAutoJoinAdmission(state, now)
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
	d := diagnoseAutoJoinAdmission(state, now)
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
	d := diagnoseAutoJoinAdmission(state, now)
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
	d := diagnoseAutoJoinAdmission(state, now)
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
	d := diagnoseAutoJoinAdmission(state, now)
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
	d := diagnoseAutoJoinAdmission(state, now)
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
	d := diagnoseAutoJoinAdmission(state, now)
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
	updateAdmissionOnPending(state, now)
	if state.Admission == nil {
		t.Fatalf("admission state should be initialized")
	}
	if !state.Admission.Pending {
		t.Fatalf("should be pending")
	}
	if state.Admission.PendingSinceUnix != now.Unix() {
		t.Fatalf("pending_since = %d, want %d", state.Admission.PendingSinceUnix, now.Unix())
	}
	if state.Admission.PendingReason == "" {
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
	updateAdmissionOnPending(state, time.Unix(5000, 0))
	if state.Admission.PendingSinceUnix != originalTime.Unix() {
		t.Fatalf("pending_since = %d, want %d (should be preserved)", state.Admission.PendingSinceUnix, originalTime.Unix())
	}
}

func TestRecordAdoptionResultSuccess(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", true)
	now := time.Unix(8000, 0)
	state.Admission = &admissionState{Pending: true, PendingSinceUnix: now.Add(-1 * time.Hour).Unix()}
	recordAdoptionResult(state, true, nil, now)
	if state.Admission.Pending {
		t.Fatalf("should not be pending after adoption")
	}
	if state.Admission.AdoptedAtUnix != now.Unix() {
		t.Fatalf("adopted_at = %d, want %d", state.Admission.AdoptedAtUnix, now.Unix())
	}
	if state.Admission.LastAdoptionError != "" {
		t.Fatalf("last_adoption_error should be cleared, got %s", state.Admission.LastAdoptionError)
	}
}

func TestRecordAdoptionResultFailure(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", true)
	now := time.Unix(8000, 0)
	state.Admission = &admissionState{Pending: true, PendingSinceUnix: now.Add(-1 * time.Hour).Unix()}
	adoptionErr := errors.New("test adoption failure")
	recordAdoptionResult(state, false, adoptionErr, now)
	if !state.Admission.Pending {
		t.Fatalf("should still be pending after failed adoption")
	}
	if state.Admission.LastAdoptionError != adoptionErr.Error() {
		t.Fatalf("last_adoption_error = %q, want %q", state.Admission.LastAdoptionError, adoptionErr.Error())
	}
}

func TestRecordBootstrapSyncSuccess(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", true)
	now := time.Unix(6000, 0)
	state.Admission = &admissionState{Pending: true}
	config := &syncConfigFile{
		Bootstrap: []syncConfigPeer{{ID: "catofes.", Addr: "127.0.0.1:33434"}},
	}
	recordBootstrapSyncSuccess(state, "catofes.", config, now)
	if state.Admission.LastBootstrapSyncUnix != now.Unix() {
		t.Fatalf("last_bootstrap_sync = %d, want %d", state.Admission.LastBootstrapSyncUnix, now.Unix())
	}
}

func TestRecordBootstrapSyncIgnoresNonBootstrapPeer(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", true)
	now := time.Unix(6000, 0)
	state.Admission = &admissionState{Pending: true}
	config := &syncConfigFile{
		Bootstrap: []syncConfigPeer{{ID: "catofes.", Addr: "127.0.0.1:33434"}},
	}
	recordBootstrapSyncSuccess(state, "other.peer.", config, now)
	if state.Admission.LastBootstrapSyncUnix != 0 {
		t.Fatalf("last_bootstrap_sync should remain 0 for non-bootstrap peer")
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

	updateAdmissionOnPending(state, time.Unix(1000, 0))
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
