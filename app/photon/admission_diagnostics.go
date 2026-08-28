package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

// diagnoseAutoJoinAdmission combines the common verified identity/network
// with loss-tolerant Linux admission history. It is pure and performs no I/O.
func diagnoseAutoJoinAdmission(verified *corestate.VerifiedState, admission *admissionState, now time.Time) inspect.AdmissionDiagnosis {
	if verified == nil {
		return inspect.AdmissionDiagnosis{}
	}
	d := inspect.AdmissionDiagnosis{
		ManagedZone: verified.ManagedZone,
		ParentZone:  verified.ManagedZone.Parent(),
	}
	if admission != nil {
		d.LastBootstrapSyncUnix = admission.LastBootstrapSyncUnix
		d.PendingSinceUnix = admission.PendingSinceUnix
		d.AdoptedAtUnix = admission.AdoptedAtUnix
		d.LastAdoptionError = admission.LastAdoptionError
	}

	if !autoJoinPendingVerified(verified) {
		d.Pending = false
		if admission != nil && admission.AdoptedAtUnix > 0 {
			d.Reason = inspect.AdmissionReasonAdopted
		} else {
			d.Reason = inspect.AdmissionReasonNotApplicable
		}
		return d
	}

	d.Pending = true

	// Build join request for diagnostics.
	if len(verified.IdentityPrivateKey) == ed25519.PrivateKeySize {
		d.HasZonePrivateKey = true
		pub := verified.IdentityPrivateKey.Public().(ed25519.PublicKey)
		request := joinRequest{Version: 1, Zone: verified.ManagedZone, PublicKey: pub}
		if text, err := encodeBase64JSON(&request); err == nil {
			d.JoinRequestB64 = text
		}
	} else {
		d.Reason = inspect.AdmissionReasonMissingZoneKey
		d.ReasonDetail = "zone private key is not loaded; check identity.key_path in config"
		return d
	}

	// Check parent zone presence.
	if verified.Network == nil {
		d.Reason = inspect.AdmissionReasonMissingParentZone
		d.ReasonDetail = "network state is empty; bootstrap peer must sync the parent zone"
		return d
	}
	parentState := verified.Network.Zones[d.ParentZone]
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
	delegation := parentState.Delegations[verified.ManagedZone]
	if delegation == nil {
		d.Reason = inspect.AdmissionReasonMissingDelegation
		d.ReasonDetail = fmt.Sprintf("parent zone %s has no delegation for %s; parent zone admin must run 'delegate issue'", d.ParentZone, verified.ManagedZone)
		return d
	}
	d.DelegationKnown = true

	// Check delegation key match.
	pub := verified.IdentityPrivateKey.Public().(ed25519.PublicKey)
	if delegation.ZoneName != verified.ManagedZone || delegation.Authority.Zone != verified.ManagedZone || !authorityHasKey(&delegation.Authority, pub) {
		d.Reason = inspect.AdmissionReasonDelegationKeyMismatch
		d.ReasonDetail = "delegation authority does not match local zone private key; parent zone admin may have signed for a different public key"
		return d
	}
	d.DelegationKeyMatches = true

	// Check VerifyDelegation.
	if err := photoncrypto.VerifyDelegation(delegation, parentState.Authority, d.ParentZone, now); err != nil {
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

func debugAdmission() error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := admissionStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online peer_id=%s\n", response.PeerID)
		if response.Admission != nil {
			return inspecttext.WriteAdmissionDiagnosis(os.Stdout, *response.Admission)
		}
		fmt.Printf("admission: not available from daemon\n")
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	diagnosis := diagnoseAutoJoinAdmission(&corestate.VerifiedState{
		ManagedZone: state.ManagedZone, Network: state.Network, IdentityPrivateKey: state.ZonePrivateKey,
	}, state.Admission, rt.Now())
	return inspecttext.WriteAdmissionDiagnosis(os.Stdout, diagnosis)
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
		d := diagnoseAutoJoinAdmission(&corestate.VerifiedState{
			ManagedZone: state.ManagedZone, Network: state.Network, IdentityPrivateKey: state.ZonePrivateKey,
		}, state.Admission, now)
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
