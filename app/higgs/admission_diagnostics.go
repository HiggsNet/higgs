package main

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

// diagnoseAutoJoinAdmission examines the local state and produces a
// structured admission diagnosis explaining why a node is (or is not)
// in auto-join pending state. The function is pure: it does not mutate
// state or perform I/O.
func diagnoseAutoJoinAdmission(state *stateFile, now time.Time) inspect.AdmissionDiagnosis {
	d := inspect.AdmissionDiagnosis{
		ManagedZone: state.ManagedZone,
		ParentZone:  state.ManagedZone.Parent(),
	}
	if state.Admission != nil {
		d.LastBootstrapSyncUnix = state.Admission.LastBootstrapSyncUnix
		d.PendingSinceUnix = state.Admission.PendingSinceUnix
		d.AdoptedAtUnix = state.Admission.AdoptedAtUnix
		d.LastAdoptionError = state.Admission.LastAdoptionError
	}

	if !autoJoinPending(state) {
		d.Pending = false
		if state.Admission != nil && state.Admission.AdoptedAtUnix > 0 {
			d.Reason = inspect.AdmissionReasonAdopted
		} else {
			d.Reason = inspect.AdmissionReasonNotApplicable
		}
		return d
	}

	d.Pending = true

	// Build join request for diagnostics.
	if len(state.ZonePrivateKey) == ed25519.PrivateKeySize {
		d.HasZonePrivateKey = true
		pub := state.ZonePrivateKey.Public().(ed25519.PublicKey)
		request := joinRequest{Version: 1, Zone: state.ManagedZone, PublicKey: pub}
		if text, err := encodeBase64JSON(&request); err == nil {
			d.JoinRequestB64 = text
		}
	} else {
		d.Reason = inspect.AdmissionReasonMissingZoneKey
		d.ReasonDetail = "zone private key is not loaded; check identity.key_path in config"
		return d
	}

	// Check parent zone presence.
	if state.Network == nil {
		d.Reason = inspect.AdmissionReasonMissingParentZone
		d.ReasonDetail = "network state is empty; bootstrap peer must sync the parent zone"
		return d
	}
	parentState := state.Network.Zones[d.ParentZone]
	if parentState == nil {
		d.Reason = inspect.AdmissionReasonMissingParentZone
		d.ReasonDetail = fmt.Sprintf("parent zone %s is not in local verified state; waiting for bootstrap sync", d.ParentZone)
		return d
	}
	d.ParentZoneKnown = true
	if parentState.Authority == nil {
		d.Reason = inspect.AdmissionReasonMissingParentZone
		d.ReasonDetail = fmt.Sprintf("parent zone %s has no authority; waiting for bootstrap sync", d.ParentZone)
		return d
	}
	d.ParentAuthorityKnown = true

	// Check delegation presence.
	delegation := parentState.Delegations[state.ManagedZone]
	if delegation == nil {
		d.Reason = inspect.AdmissionReasonMissingDelegation
		d.ReasonDetail = fmt.Sprintf("parent zone %s has no delegation for %s; parent zone admin must run 'delegate issue'", d.ParentZone, state.ManagedZone)
		return d
	}
	d.DelegationKnown = true

	// Check delegation key match.
	pub := state.ZonePrivateKey.Public().(ed25519.PublicKey)
	if delegation.ZoneName != state.ManagedZone || delegation.Authority.Zone != state.ManagedZone || !authorityHasKey(&delegation.Authority, pub) {
		d.Reason = inspect.AdmissionReasonDelegationKeyMismatch
		d.ReasonDetail = "delegation authority does not match local zone private key; parent zone admin may have signed for a different public key"
		return d
	}
	d.DelegationKeyMatches = true

	// Check VerifyDelegation.
	if err := higgscrypto.VerifyDelegation(delegation, parentState.Authority, d.ParentZone, now); err != nil {
		d.Reason = inspect.AdmissionReasonVerifyDelegationFailed
		d.ReasonDetail = fmt.Sprintf("VerifyDelegation failed: %v", err)
		return d
	}

	// All checks pass — either we should be adopted on next sync, or
	// VerifyChain would fail if we tried to materialize now.
	d.Reason = inspect.AdmissionReasonWaitingForAdoption
	if d.LastBootstrapSyncUnix == 0 {
		d.Reason = inspect.AdmissionReasonNoBootstrapSync
		d.ReasonDetail = "no bootstrap peer has successfully synced yet; check bootstrap config and peer reachability"
	} else {
		d.ReasonDetail = "all local checks pass; adoption will complete on next sync round that applies the delegation"
	}

	return d
}

// updateAdmissionOnPending records the current pending diagnosis into the
// admission state. It should be called when the daemon detects it is in
// pending state, e.g. at startup or after a sync round that did not
// result in adoption.
func updateAdmissionOnPending(state *stateFile, now time.Time) {
	if state == nil {
		return
	}
	pending := autoJoinPending(state)
	if state.Admission == nil {
		state.Admission = &admissionState{}
	}
	if pending {
		if state.Admission.PendingSinceUnix == 0 {
			state.Admission.PendingSinceUnix = now.Unix()
		}
		state.Admission.Pending = true
		state.Admission.AdoptedAtUnix = 0
		d := diagnoseAutoJoinAdmission(state, now)
		state.Admission.PendingReason = d.Reason
		state.Admission.PendingReasonDetail = d.ReasonDetail
		state.Admission.JoinRequestB64 = d.JoinRequestB64
	} else {
		// Not pending — clear pending fields but preserve adopted timestamp.
		if state.Admission.Pending {
			state.Admission.Pending = false
			state.Admission.AdoptedAtUnix = now.Unix()
			state.Admission.PendingReason = ""
			state.Admission.PendingReasonDetail = ""
		}
	}
}

// recordAdoptionResult updates the admission state after an adoption attempt.
// If adopted is true, the node has transitioned out of pending. If err is
// non-nil, the error is recorded for diagnostics.
func recordAdoptionResult(state *stateFile, adopted bool, err error, now time.Time) {
	if state == nil {
		return
	}
	if state.Admission == nil {
		state.Admission = &admissionState{}
	}
	if adopted {
		state.Admission.Pending = false
		state.Admission.AdoptedAtUnix = now.Unix()
		state.Admission.LastAdoptionError = ""
		state.Admission.PendingReason = ""
		state.Admission.PendingReasonDetail = ""
		return
	}
	if err != nil {
		state.Admission.LastAdoptionError = err.Error()
		state.Admission.Pending = true
		if state.Admission.PendingSinceUnix == 0 {
			state.Admission.PendingSinceUnix = now.Unix()
		}
	}
}

// recordBootstrapSyncSuccess updates the last successful bootstrap sync
// timestamp in admission state. It should be called after a successful
// outbound sync round with a bootstrap peer while the node is pending.
func recordBootstrapSyncSuccess(state *stateFile, peerID string, config *syncConfigFile, now time.Time) {
	if state == nil || state.Admission == nil || !state.Admission.Pending {
		return
	}
	if !isBootstrapPeer(config, peerID) {
		return
	}
	state.Admission.LastBootstrapSyncUnix = now.Unix()
}
