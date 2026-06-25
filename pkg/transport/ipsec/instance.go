package ipsec

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

const (
	LinkStatePending     = "pending"
	LinkStateConfiguring = "configuring"
	LinkStateConnecting  = "connecting"
	LinkStateUp          = "up"
	LinkStateDegraded    = "degraded"
	LinkStateStale       = "stale"
	LinkStateRemoving    = "removing"
	LinkStateDown        = "down"
	LinkStateError       = "error"

	ReconcileActionAdopt          = "adopt"
	ReconcileActionCreate         = "create"
	ReconcileActionUpdate         = "update"
	ReconcileActionRepair         = "repair"
	ReconcileActionTeardown       = "teardown"
	ReconcileActionNoop           = "noop"
	ReconcileActionPrepareRotate  = "prepare_rotate"
	ReconcileActionCommitRotate   = "commit_rotate"
	ReconcileActionRollbackRotate = "rollback_rotate"
	ReconcileActionCleanupRotate  = "cleanup_rotate"

	RotatePhaseIdle        = ""
	RotatePhasePreparing   = "preparing"
	RotatePhaseTestingNew  = "testing_new"
	RotatePhaseDualRunning = "dual_running"
	RotatePhaseCutover     = "cutover"
	RotatePhaseRollback    = "rollback"
	RotatePhaseCleanup     = "cleanup"

	TakeoverPhaseIdle     = ""
	TakeoverPhaseDelay    = "delay"
	TakeoverPhaseActive   = "active"
	TakeoverPhaseCooldown = "cooldown"

	defaultLinkEstablishGrace = 3 * time.Minute
)

type LinkInstance struct {
	ID                  string
	GroupID             string
	PeerZone            zone.ZonePath
	TransportKind       string
	TransportID         string
	DesiredSpecHash     string
	ActualState         string
	InterfaceName       string
	XFRMIfID            uint32
	IKEName             string
	ChildSAName         string
	Endpoint            string
	SelectedContact     ContactPoint
	RemoteGeneration    uint64
	StagedGeneration    uint64
	RotatePhase         string
	StagedIKEName       string
	StagedChildSAName   string
	StagedInterfaceName string
	StagedXFRMIfID      uint32
	RotateDeadline      int64
	LastError           string
	FailureCount        int
	BackoffUntil        int64
	LastTransition      int64
	Owner               ResourceOwner

	// Bidirectional takeover state (Phase 4.5).
	InitiatorRole     string
	TakeoverPhase     string
	TakeoverStartedAt int64
	TakeoverUntil     int64
	LastTakeoverError string
	ObservedInitiator string
}

type ResourceOwner struct {
	Manager     string
	GroupID     string
	InstanceID  string
	TransportID string
	Token       string
}

type ReconcileInputs struct {
	Desired              []TransportLinkSpec
	Instances            map[string]LinkInstance
	SAs                  []SAState
	Now                  time.Time
	Revoked              map[zone.ZonePath]bool
	Roles                map[string]string
	GroupBackoff         map[string]BackoffPolicy
	GroupRotateRetention map[string]int
	RotateCutoverReady   map[string]bool
}

type ReconcileResult struct {
	Actions   []ReconcileAction
	Instances map[string]LinkInstance
}

type ReconcileAction struct {
	Action   string
	Spec     *TransportLinkSpec
	Instance *LinkInstance
	Reason   string
}

func NewLinkInstance(spec TransportLinkSpec, state string, now time.Time) LinkInstance {
	if state == "" {
		state = LinkStatePending
	}
	inst := LinkInstance{
		ID:              LinkInstanceID(spec),
		GroupID:         spec.OverlayID,
		PeerZone:        spec.PeerZone,
		TransportKind:   spec.Provider,
		TransportID:     spec.TransportID,
		DesiredSpecHash: TransportLinkSpecHash(spec),
		ActualState:     state,
		InterfaceName:   spec.InterfaceName,
		XFRMIfID:        spec.XFRMIfID,
		IKEName:         spec.TransportID,
		ChildSAName:     ChildSAName(spec),
		Endpoint:        endpointForSpec(spec),
		LastTransition:  now.Unix(),
		InitiatorRole:   spec.InitiatorRole,
		Owner: ResourceOwner{
			Manager:     "higgs",
			GroupID:     spec.OverlayID,
			InstanceID:  LinkInstanceID(spec),
			TransportID: spec.TransportID,
			Token:       ResourceOwnerToken(spec.OverlayID, LinkInstanceID(spec), spec.TransportID),
		},
	}
	if point, ok := firstContactPoint(spec.ContactPoints); ok {
		inst.SelectedContact = point
		inst.RemoteGeneration = point.Generation
		inst.Endpoint = contactEndpoint(point)
	}
	return inst
}

func LinkInstanceID(spec TransportLinkSpec) string {
	if spec.TransportID != "" {
		return spec.TransportID
	}
	return StableTransportID(spec.LocalZone, spec.PeerZone, spec.OverlayID)
}

func TransportLinkSpecHash(spec TransportLinkSpec) string {
	// Runtime metadata must not change the desired spec hash; otherwise
	// standby -> takeover -> converged transitions and per-address
	// success/failure/backoff fluctuations would emit unnecessary update
	// actions for an otherwise identical StrongSwan configuration.
	spec.InitiatorRole = ""
	for i := range spec.ContactPoints {
		cp := &spec.ContactPoints[i]
		cp.Successes = 0
		cp.Failures = 0
		cp.BackoffUntil = time.Time{}
		cp.LastError = ""
		cp.RankReason = ""
	}
	data, err := json.Marshal(spec)
	if err != nil {
		panic(fmt.Sprintf("marshal transport link spec: %v", err))
	}
	sum := higgscrypto.Hash(data)
	return hex.EncodeToString(sum[:])
}

func ResourceOwnerToken(groupID, instanceID, transportID string) string {
	sum := higgscrypto.Hash([]byte("higgs.ipsec.owner.v1"), []byte{0}, []byte(groupID), []byte{0}, []byte(instanceID), []byte{0}, []byte(transportID))
	return hex.EncodeToString(sum[:8])
}

func (o ResourceOwner) Validate(instance LinkInstance) error {
	if o.Manager != "higgs" {
		return fmt.Errorf("resource is not managed by higgs")
	}
	if o.GroupID == "" || o.InstanceID == "" || o.TransportID == "" {
		return fmt.Errorf("resource owner is incomplete")
	}
	if o.GroupID != instance.GroupID {
		return fmt.Errorf("owner group %q does not match instance group %q", o.GroupID, instance.GroupID)
	}
	if o.InstanceID != instance.ID {
		return fmt.Errorf("owner instance %q does not match instance %q", o.InstanceID, instance.ID)
	}
	if o.TransportID != instance.TransportID {
		return fmt.Errorf("owner transport %q does not match instance transport %q", o.TransportID, instance.TransportID)
	}
	if o.Token != "" && o.Token != ResourceOwnerToken(o.GroupID, o.InstanceID, o.TransportID) {
		return fmt.Errorf("resource owner token mismatch")
	}
	if instance.TransportID != "" && !strings.HasPrefix(instance.TransportID, "ipsec-") {
		return fmt.Errorf("transport id %q does not use higgs ipsec naming", instance.TransportID)
	}
	if instance.InterfaceName != "" && !strings.HasPrefix(instance.InterfaceName, "hgs") {
		return fmt.Errorf("interface %q does not use higgs naming", instance.InterfaceName)
	}
	return nil
}

func contactGeneration(spec TransportLinkSpec) uint64 {
	if spec.Generation != 0 {
		return spec.Generation
	}
	point, ok := firstContactPoint(spec.ContactPoints)
	if !ok {
		return 0
	}
	return point.Generation
}

func rotateSpec(base TransportLinkSpec, generation uint64) TransportLinkSpec {
	spec := base
	spec.TransportID = RotateConnectionName(base.TransportID, generation)
	spec.XFRMIfID = StableXFRMIfID(base.LocalZone, base.PeerZone, spec.TransportID)
	spec.InterfaceName = StableInterfaceName(spec.XFRMIfID)
	var contacts []ContactPoint
	for _, point := range base.ContactPoints {
		if point.Generation == generation {
			contacts = append(contacts, point)
		}
	}
	if len(contacts) == 0 {
		contacts = append([]ContactPoint(nil), base.ContactPoints...)
	}
	spec.ContactPoints = contacts
	return spec
}

func rotateSpecForRole(base TransportLinkSpec, generation uint64, role string) TransportLinkSpec {
	spec := rotateSpec(base, generation)
	if !IsActiveInitiatorRole(role) {
		spec.ContactPoints = nil
	}
	return spec
}

func findStagedSA(states []SAState, inst LinkInstance) SAState {
	if inst.StagedIKEName == "" {
		return SAState{}
	}
	for _, state := range states {
		if state.Name == inst.StagedIKEName || state.ChildSA == inst.StagedChildSAName {
			return state
		}
	}
	return SAState{}
}

func rotateTimeout() time.Duration {
	return 2 * time.Minute
}

func ReconcileLinkInstances(in ReconcileInputs) ReconcileResult {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	result := ReconcileResult{Instances: map[string]LinkInstance{}}
	for id, inst := range in.Instances {
		result.Instances[id] = inst
	}
	desiredByID := map[string]TransportLinkSpec{}
	for _, spec := range in.Desired {
		desiredByID[LinkInstanceID(spec)] = spec
	}
	for id, spec := range desiredByID {
		existing, exists := result.Instances[id]
		if in.Revoked[spec.PeerZone] {
			inst := existing
			if !exists {
				inst = NewLinkInstance(spec, LinkStateRemoving, now)
			}
			inst.ActualState = LinkStateRemoving
			inst.LastTransition = now.Unix()
			result.Instances[id] = inst
			result.add(ReconcileActionTeardown, nil, &inst, "peer revoked")
			continue
		}
		role := roleForSpec(id, in.Roles)
		if role == InitiatorRoleSecondaryStandby {
			sa := findInstanceSA(in.SAs, existing)
			if !sa.Established {
				sa = findMatchingSA(in.SAs, spec)
			}
			result.reconcileSecondaryStandby(id, spec, existing, exists, sa, in.SAs, in.GroupBackoff, in.GroupRotateRetention, in.RotateCutoverReady, now)
			continue
		}
		// Primary / outbound initiator path.
		desiredGen := contactGeneration(spec)
		if !exists {
			sa := findMatchingSA(in.SAs, spec)
			inst := NewLinkInstance(spec, LinkStatePending, now)
			if sa.Established {
				inst.ActualState = LinkStateUp
				inst.Endpoint = sa.Endpoint
				result.add(ReconcileActionAdopt, &spec, &inst, "driver state already exists")
			} else {
				inst.ActualState = LinkStateConfiguring
				result.add(ReconcileActionCreate, &spec, &inst, "missing instance")
			}
			result.Instances[id] = inst
			continue
		}
		if existing.RemoteGeneration == 0 {
			existing.RemoteGeneration = desiredGen
		}
		if existing.RemoteGeneration != desiredGen {
			result.handleRotate(id, spec, existing, in.SAs, rotateRetentionForSpec(spec, in.GroupRotateRetention), rotateCutoverReady(id, in.RotateCutoverReady), now, role)
			continue
		}
		existing = result.clearStagedIfIdle(existing, in.SAs, now)
		sa := findInstanceSA(in.SAs, existing)
		specHash := TransportLinkSpecHash(spec)
		if existing.DesiredSpecHash != specHash {
			if inLinkBackoff(existing, now) {
				result.add(ReconcileActionNoop, &spec, &existing, "apply backoff active")
				continue
			}
			inst := NewLinkInstance(spec, LinkStateConfiguring, now)
			inst.FailureCount = existing.FailureCount
			inst.BackoffUntil = existing.BackoffUntil
			inst.LastError = existing.LastError
			result.Instances[id] = inst
			result.add(ReconcileActionUpdate, &spec, &inst, "desired spec changed")
			if existing.IKEName != "" && existing.IKEName != spec.TransportID {
				oldSpec := TransportLinkSpec{
					PeerZone:      existing.PeerZone,
					TransportID:   existing.IKEName,
					InterfaceName: existing.InterfaceName,
					XFRMIfID:      existing.XFRMIfID,
				}
				result.add(ReconcileActionCleanupRotate, &oldSpec, &inst, "old rotated connection after spec update")
			}
			continue
		}
		if sa.Established && existing.ActualState != LinkStateUp {
			inst := existing
			inst.ActualState = LinkStateUp
			inst.Endpoint = sa.Endpoint
			inst.FailureCount = 0
			inst.BackoffUntil = 0
			inst.LastError = ""
			inst.LastTransition = now.Unix()
			result.Instances[id] = inst
			result.add(ReconcileActionAdopt, &spec, &inst, "driver state recovered")
			continue
		}
		if inLinkBackoff(existing, now) {
			result.add(ReconcileActionNoop, &spec, &existing, "apply backoff active")
			continue
		}
		if (existing.ActualState == LinkStateConfiguring || existing.ActualState == LinkStateConnecting) && !sa.Established {
			if saObserved(sa) {
				if !linkEstablishing(existing, now) {
					inst := MarkLinkApplyFailure(existing, groupBackoffForSpec(spec, in.GroupBackoff), now, fmt.Errorf("waiting for in-progress SA"))
					result.Instances[id] = inst
					result.add(ReconcileActionNoop, &spec, &inst, "awaiting in-progress sa")
					continue
				}
				result.add(ReconcileActionNoop, &spec, &existing, "awaiting in-progress sa")
				continue
			}
			if linkAutostartEstablishing(existing, groupBackoffForSpec(spec, in.GroupBackoff), now) {
				result.add(ReconcileActionNoop, &spec, &existing, "awaiting established sa")
				continue
			}
			inst := MarkLinkApplyFailure(existing, groupBackoffForSpec(spec, in.GroupBackoff), now, fmt.Errorf("waiting for established SA"))
			result.Instances[id] = inst
			result.add(ReconcileActionNoop, &spec, &inst, "awaiting established sa")
			continue
		}
		if (existing.ActualState == LinkStateError || existing.ActualState == LinkStateDegraded) && !sa.Established {
			inst := existing
			inst.ActualState = LinkStateDegraded
			inst.LastTransition = now.Unix()
			result.Instances[id] = inst
			result.add(ReconcileActionRepair, &spec, &inst, "previous apply failed")
			continue
		}
		if existing.ActualState == LinkStateUp && !sa.Established {
			inst := existing
			inst.ActualState = LinkStateDegraded
			inst.LastTransition = now.Unix()
			result.Instances[id] = inst
			result.add(ReconcileActionRepair, &spec, &inst, "driver state missing")
			continue
		}
		inst := existing
		result.add(ReconcileActionNoop, &spec, &inst, "")
	}
	for id, inst := range result.Instances {
		if _, ok := desiredByID[id]; ok {
			continue
		}
		if err := inst.Owner.Validate(inst); err != nil {
			result.add(ReconcileActionNoop, nil, &inst, "unmanaged resource retained: "+err.Error())
			continue
		}
		inst.ActualState = LinkStateRemoving
		inst.LastTransition = now.Unix()
		result.Instances[id] = inst
		result.add(ReconcileActionTeardown, nil, &inst, "no longer desired")
	}
	return result
}

func (r *ReconcileResult) reconcileSecondaryStandby(id string, spec TransportLinkSpec, existing LinkInstance, exists bool, sa SAState, sas []SAState, groupBackoff map[string]BackoffPolicy, groupRotateRetention map[string]int, rotateCutover map[string]bool, now time.Time) {
	policy := groupBackoffForSpec(spec, groupBackoff)
	if sa.Established {
		if exists {
			desiredGen := contactGeneration(spec)
			if existing.RemoteGeneration == 0 {
				existing.RemoteGeneration = desiredGen
			}
			if existing.RemoteGeneration != desiredGen {
				rotateRole := InitiatorRoleSecondaryStandby
				if existing.InitiatorRole == InitiatorRoleSecondaryTakeover {
					rotateRole = InitiatorRoleSecondaryTakeover
				}
				r.handleRotate(id, spec, existing, sas, rotateRetentionForSpec(spec, groupRotateRetention), rotateCutoverReady(id, rotateCutover), now, rotateRole)
				return
			}
		}
		inst := existing
		if !exists {
			inst = NewLinkInstance(spec, LinkStateUp, now)
		}
		inst.ActualState = LinkStateUp
		inst.Endpoint = sa.Endpoint
		inst.DesiredSpecHash = TransportLinkSpecHash(spec)
		inst.InitiatorRole = InitiatorRoleConverged
		inst.TakeoverPhase = TakeoverPhaseIdle
		inst.TakeoverUntil = 0
		inst.LastTakeoverError = ""
		inst.LastTransition = now.Unix()
		r.Instances[id] = inst
		r.add(ReconcileActionAdopt, &spec, &inst, "driver state already exists")
		return
	}
	if !exists {
		inst := NewLinkInstance(spec, LinkStateDown, now)
		inst.InitiatorRole = InitiatorRoleSecondaryStandby
		r.Instances[id] = inst
		r.add(ReconcileActionNoop, &spec, &inst, "bidirectional_standby")
		return
	}
	inst := existing
	switch inst.InitiatorRole {
	case InitiatorRoleSecondaryTakeover:
		if inLinkBackoff(inst, now) {
			r.add(ReconcileActionNoop, &spec, &inst, "apply backoff active")
			return
		}
		if inst.TakeoverPhase == TakeoverPhaseCooldown && now.Before(time.Unix(inst.TakeoverUntil, 0)) {
			r.add(ReconcileActionNoop, &spec, &inst, "takeover_cooldown_active")
			return
		}
		lease := TakeoverLeaseDuration(policy)
		if (inst.ActualState == LinkStateConfiguring || inst.ActualState == LinkStateConnecting) &&
			now.After(time.Unix(inst.TakeoverStartedAt, 0).Add(lease)) {
			inst.ActualState = LinkStateError
			inst.LastError = "secondary takeover timed out waiting for SA"
			inst.LastTransition = now.Unix()
			inst.TakeoverPhase = TakeoverPhaseCooldown
			inst.TakeoverUntil = now.Add(TakeoverCooldownDuration(policy)).Unix()
			inst.LastTakeoverError = inst.LastError
			r.Instances[id] = inst
			r.add(ReconcileActionRepair, &spec, &inst, "secondary_takeover_timeout")
			return
		}
		if inst.ActualState == LinkStateError || inst.ActualState == LinkStateDegraded {
			inst.ActualState = LinkStateDegraded
			inst.LastTransition = now.Unix()
			r.Instances[id] = inst
			r.add(ReconcileActionRepair, &spec, &inst, "secondary_takeover_retry")
			return
		}
		if inst.ActualState == LinkStateConfiguring || inst.ActualState == LinkStateConnecting {
			r.add(ReconcileActionNoop, &spec, &inst, "secondary_takeover_pending")
			return
		}
	case InitiatorRoleConverged:
		if inLinkBackoff(inst, now) {
			r.add(ReconcileActionNoop, &spec, &inst, "apply backoff active")
			return
		}
		inst.ActualState = LinkStateDegraded
		inst.LastTransition = now.Unix()
		r.Instances[id] = inst
		r.add(ReconcileActionRepair, &spec, &inst, "driver state missing after convergence")
		return
	}
	ok, reason := shouldSecondaryTakeover(inst, InitiatorRoleSecondaryStandby, spec, sa, policy, now)
	if !ok {
		r.add(ReconcileActionNoop, &spec, &inst, reason)
		return
	}
	inst.InitiatorRole = InitiatorRoleSecondaryTakeover
	inst.TakeoverPhase = TakeoverPhaseActive
	inst.TakeoverStartedAt = now.Unix()
	inst.TakeoverUntil = now.Add(TakeoverLeaseDuration(policy)).Unix()
	inst.LastError = ""
	inst.LastTransition = now.Unix()
	inst.ActualState = LinkStateConfiguring
	inst.DesiredSpecHash = TransportLinkSpecHash(spec)
	r.Instances[id] = inst
	r.add(ReconcileActionCreate, &spec, &inst, reason)
}

func (r *ReconcileResult) handleRotate(id string, spec TransportLinkSpec, existing LinkInstance, sas []SAState, retention time.Duration, cutoverReady bool, now time.Time, initiatorRole string) {
	desiredGen := contactGeneration(spec)
	if existing.StagedGeneration != 0 && existing.StagedGeneration != desiredGen {
		inst := existing
		inst.RotatePhase = RotatePhaseCleanup
		r.Instances[id] = inst
		stagedSpec := rotateSpecForRole(spec, existing.StagedGeneration, initiatorRole)
		r.add(ReconcileActionCleanupRotate, &stagedSpec, &inst, "stale staged generation")
		return
	}
	if inLinkBackoff(existing, now) {
		r.add(ReconcileActionNoop, &spec, &existing, "rotate backoff active")
		return
	}
	if existing.StagedGeneration == desiredGen {
		stagedSA := findStagedSA(sas, existing)
		stagedSpec := rotateSpecForRole(spec, existing.StagedGeneration, initiatorRole)
		stagedInterfaceName := firstNonEmptyString(existing.StagedInterfaceName, stagedSpec.InterfaceName)
		stagedXFRMIfID := firstNonZeroUint32(existing.StagedXFRMIfID, stagedSpec.XFRMIfID)
		if stagedSA.Established {
			oldSA := findInstanceSA(sas, existing)
			if oldSA.Established && retention > 0 && (existing.RotatePhase != RotatePhaseDualRunning || existing.RotateDeadline == 0) {
				inst := existing
				inst.ActualState = LinkStateUp
				inst.RotatePhase = RotatePhaseDualRunning
				inst.RotateDeadline = now.Add(retention).Unix()
				inst.LastTransition = now.Unix()
				r.Instances[id] = inst
				r.add(ReconcileActionNoop, &spec, &inst, "rotate retention active")
				return
			}
			if oldSA.Established && existing.RotatePhase == RotatePhaseDualRunning && existing.RotateDeadline != 0 && now.Before(time.Unix(existing.RotateDeadline, 0)) {
				inst := existing
				inst.ActualState = LinkStateUp
				inst.RotatePhase = RotatePhaseDualRunning
				r.Instances[id] = inst
				r.add(ReconcileActionNoop, &spec, &inst, "rotate retention active")
				return
			}
			if oldSA.Established && !cutoverReady {
				inst := existing
				inst.ActualState = LinkStateUp
				inst.RotatePhase = RotatePhaseDualRunning
				r.Instances[id] = inst
				r.add(ReconcileActionNoop, &spec, &inst, "route_cutover_pending")
				return
			}
			inst := existing
			inst.RemoteGeneration = desiredGen
			inst.IKEName = existing.StagedIKEName
			inst.ChildSAName = existing.StagedChildSAName
			inst.InterfaceName = stagedInterfaceName
			inst.XFRMIfID = stagedXFRMIfID
			inst.ActualState = LinkStateUp
			inst.Endpoint = stagedSA.Endpoint
			if point, ok := firstContactPointForGeneration(spec, desiredGen); ok {
				inst.SelectedContact = point
				inst.Endpoint = contactEndpoint(point)
			}
			inst.DesiredSpecHash = TransportLinkSpecHash(spec)
			inst.StagedGeneration = 0
			inst.StagedIKEName = ""
			inst.StagedChildSAName = ""
			inst.StagedInterfaceName = ""
			inst.StagedXFRMIfID = 0
			inst.RotatePhase = RotatePhaseIdle
			inst.RotateDeadline = 0
			inst.FailureCount = 0
			inst.BackoffUntil = 0
			inst.LastError = ""
			inst.LastTransition = now.Unix()
			r.Instances[id] = inst
			oldSpec := TransportLinkSpec{
				PeerZone:      existing.PeerZone,
				TransportID:   existing.IKEName,
				InterfaceName: existing.InterfaceName,
				XFRMIfID:      existing.XFRMIfID,
				ContactPoints: []ContactPoint{existing.SelectedContact},
			}
			r.add(ReconcileActionCommitRotate, &oldSpec, &inst, "staged sa established")
			return
		}
		if existing.RotateDeadline != 0 && now.After(time.Unix(existing.RotateDeadline, 0)) {
			inst := existing
			inst.StagedGeneration = 0
			inst.StagedIKEName = ""
			inst.StagedChildSAName = ""
			inst.StagedInterfaceName = ""
			inst.StagedXFRMIfID = 0
			inst.RotatePhase = RotatePhaseRollback
			inst.RotateDeadline = 0
			inst.LastError = "staged sa not established by deadline"
			inst.FailureCount++
			inst.BackoffUntil = now.Add(nextLinkBackoff(BackoffPolicy{}, inst.FailureCount)).Unix()
			inst.LastTransition = now.Unix()
			r.Instances[id] = inst
			r.add(ReconcileActionRollbackRotate, &stagedSpec, &inst, "staged sa deadline exceeded")
			return
		}
		inst := existing
		inst.RotatePhase = RotatePhaseTestingNew
		inst.LastTransition = now.Unix()
		r.Instances[id] = inst
		r.add(ReconcileActionPrepareRotate, &stagedSpec, &inst, "awaiting staged sa")
		return
	}
	inst := existing
	inst.StagedGeneration = desiredGen
	inst.StagedIKEName = RotateConnectionName(existing.TransportID, desiredGen)
	inst.StagedChildSAName = RotateChildSAName(existing.TransportID, desiredGen)
	stagedSpec := rotateSpecForRole(spec, desiredGen, initiatorRole)
	inst.StagedInterfaceName = stagedSpec.InterfaceName
	inst.StagedXFRMIfID = stagedSpec.XFRMIfID
	inst.RotatePhase = RotatePhasePreparing
	inst.RotateDeadline = now.Add(rotateTimeout()).Unix()
	inst.LastTransition = now.Unix()
	r.Instances[id] = inst
	r.add(ReconcileActionPrepareRotate, &stagedSpec, &inst, "remote port generation changed")
}

func (r *ReconcileResult) clearStagedIfIdle(existing LinkInstance, sas []SAState, now time.Time) LinkInstance {
	if existing.StagedGeneration == 0 {
		return existing
	}
	stagedSA := findStagedSA(sas, existing)
	if stagedSA.Established {
		inst := existing
		inst.RemoteGeneration = existing.StagedGeneration
		inst.IKEName = existing.StagedIKEName
		inst.ChildSAName = existing.StagedChildSAName
		inst.InterfaceName = firstNonEmptyString(existing.StagedInterfaceName, existing.InterfaceName)
		inst.XFRMIfID = firstNonZeroUint32(existing.StagedXFRMIfID, existing.XFRMIfID)
		inst.ActualState = LinkStateUp
		inst.Endpoint = stagedSA.Endpoint
		inst.SelectedContact = ContactPoint{}
		inst.StagedGeneration = 0
		inst.StagedIKEName = ""
		inst.StagedChildSAName = ""
		inst.StagedInterfaceName = ""
		inst.StagedXFRMIfID = 0
		inst.RotatePhase = RotatePhaseDualRunning
		inst.RotateDeadline = 0
		inst.LastTransition = now.Unix()
		r.Instances[existing.ID] = inst
		oldSpec := TransportLinkSpec{
			PeerZone:      existing.PeerZone,
			TransportID:   existing.TransportID,
			InterfaceName: existing.InterfaceName,
			XFRMIfID:      existing.XFRMIfID,
			ContactPoints: []ContactPoint{existing.SelectedContact},
		}
		r.add(ReconcileActionCleanupRotate, &oldSpec, &inst, "staged sa adopted")
		return inst
	}
	inst := existing
	inst.StagedGeneration = 0
	inst.StagedIKEName = ""
	inst.StagedChildSAName = ""
	inst.StagedInterfaceName = ""
	inst.StagedXFRMIfID = 0
	inst.RotatePhase = RotatePhaseIdle
	inst.RotateDeadline = 0
	r.Instances[existing.ID] = inst
	return inst
}

func MarkLinkApplyFailure(inst LinkInstance, policy BackoffPolicy, now time.Time, err error) LinkInstance {
	if now.IsZero() {
		now = time.Now()
	}
	inst.FailureCount++
	inst.BackoffUntil = now.Add(nextLinkBackoff(policy, inst.FailureCount)).Unix()
	inst.LastTransition = now.Unix()
	inst.ActualState = LinkStateError
	if err != nil {
		inst.LastError = err.Error()
	}
	return inst
}

func MarkLinkApplySuccess(inst LinkInstance, now time.Time) LinkInstance {
	if now.IsZero() {
		now = time.Now()
	}
	inst.FailureCount = 0
	inst.BackoffUntil = 0
	inst.LastError = ""
	inst.LastTransition = now.Unix()
	return inst
}

func nextLinkBackoff(policy BackoffPolicy, failureCount int) time.Duration {
	if failureCount < 1 {
		failureCount = 1
	}
	initial := policy.InitialSeconds
	if initial <= 0 {
		initial = 1
	}
	maximum := policy.MaxSeconds
	if maximum <= 0 {
		maximum = 60
	}
	seconds := initial
	for i := 1; i < failureCount; i++ {
		if seconds >= maximum {
			return time.Duration(maximum) * time.Second
		}
		seconds *= 2
	}
	if seconds > maximum {
		seconds = maximum
	}
	return time.Duration(seconds) * time.Second
}

func inLinkBackoff(inst LinkInstance, now time.Time) bool {
	if inst.BackoffUntil == 0 || now.IsZero() {
		return false
	}
	return now.Before(time.Unix(inst.BackoffUntil, 0))
}

func roleForSpec(id string, roles map[string]string) string {
	if roles == nil {
		return InitiatorRolePrimary
	}
	if role := roles[id]; role != "" {
		return role
	}
	return InitiatorRolePrimary
}

func groupBackoffForSpec(spec TransportLinkSpec, groups map[string]BackoffPolicy) BackoffPolicy {
	if groups == nil {
		return BackoffPolicy{}
	}
	return groups[spec.OverlayID]
}

func saObserved(sa SAState) bool {
	return sa.Name != "" || sa.ChildSA != "" || sa.IKEState != "" || sa.ChildState != "" || sa.XFRMIfID != 0 || sa.Endpoint != ""
}

func linkEstablishing(inst LinkInstance, now time.Time) bool {
	if inst.LastTransition == 0 {
		return false
	}
	return now.Before(time.Unix(inst.LastTransition, 0).Add(defaultLinkEstablishGrace))
}

func linkAutostartEstablishing(inst LinkInstance, policy BackoffPolicy, now time.Time) bool {
	if inst.LastTransition == 0 {
		return false
	}
	grace := nextLinkBackoff(policy, inst.FailureCount+1) + nextLinkBackoff(policy, inst.FailureCount+2)
	return now.Before(time.Unix(inst.LastTransition, 0).Add(grace))
}

func rotateRetentionForSpec(spec TransportLinkSpec, groups map[string]int) time.Duration {
	const defaultRotateRetention = time.Hour
	if groups == nil {
		return defaultRotateRetention
	}
	seconds, ok := groups[spec.OverlayID]
	if !ok || seconds == 0 {
		return defaultRotateRetention
	}
	if seconds < 0 {
		return defaultRotateRetention
	}
	return time.Duration(seconds) * time.Second
}

func rotateCutoverReady(id string, readiness map[string]bool) bool {
	if readiness == nil {
		return true
	}
	ready, ok := readiness[id]
	if !ok {
		return true
	}
	return ready
}

func takeoverDelayFor(policy BackoffPolicy, failureCount int) time.Duration {
	if failureCount < 0 {
		failureCount = 0
	}
	// Require at least 2-3 backoff cycles before a secondary takes over.
	delay := nextLinkBackoff(policy, failureCount+2) + nextLinkBackoff(policy, failureCount+3)
	const minDelay = 60 * time.Second
	if delay < minDelay {
		return minDelay
	}
	return delay
}

func TakeoverLeaseDuration(policy BackoffPolicy) time.Duration {
	d := 5 * nextLinkBackoff(policy, 1)
	const minLease = 5 * time.Minute
	if d < minLease {
		return minLease
	}
	return d
}

func TakeoverCooldownDuration(policy BackoffPolicy) time.Duration {
	d := 3 * nextLinkBackoff(policy, 3)
	const minCooldown = 2 * time.Minute
	if d < minCooldown {
		return minCooldown
	}
	return d
}

func shouldSecondaryTakeover(inst LinkInstance, role string, spec TransportLinkSpec, sa SAState, policy BackoffPolicy, now time.Time) (bool, string) {
	if role != InitiatorRoleSecondaryStandby {
		return false, ""
	}
	if sa.Established {
		return false, ""
	}
	if inst.TakeoverPhase == TakeoverPhaseCooldown && now.Before(time.Unix(inst.TakeoverUntil, 0)) {
		return false, "takeover_cooldown_active"
	}
	if suppress, reason := suppressTakeoverDuringRotate(inst, now); suppress {
		return false, reason
	}
	if len(spec.ContactPoints) == 0 {
		return false, "takeover_no_contact_point"
	}
	// Cooldown expired after a previous failed takeover: allow retry.
	if inst.TakeoverPhase == TakeoverPhaseCooldown && !now.Before(time.Unix(inst.TakeoverUntil, 0)) {
		return true, "secondary_takeover_retry"
	}
	delay := takeoverDelayFor(policy, inst.FailureCount)
	lastTransition := time.Unix(inst.LastTransition, 0)
	switch inst.ActualState {
	case LinkStatePending, LinkStateDown, "":
		if now.Sub(lastTransition) < delay {
			return false, "takeover_delay_active"
		}
	default:
		if inst.FailureCount < 2 && now.Sub(lastTransition) < delay {
			return false, "takeover_delay_active"
		}
	}
	return true, "secondary_takeover"
}

func suppressTakeoverDuringRotate(inst LinkInstance, now time.Time) (bool, string) {
	if inst.RotateDeadline == 0 || !now.Before(time.Unix(inst.RotateDeadline, 0)) {
		return false, ""
	}
	switch inst.RotatePhase {
	case RotatePhaseDualRunning:
		return true, "rotate_retention_active"
	case RotatePhasePreparing, RotatePhaseTestingNew:
		if inst.StagedGeneration != 0 {
			return true, "rotate_staged_active"
		}
	}
	return false, ""
}

func ApplyReconcileAction(ctx context.Context, ipsec IPsecDriver, xfrm XFRMDriver, action ReconcileAction, netns NetNSSpec) (ApplyPlan, error) {
	switch action.Action {
	case ReconcileActionCreate:
		if action.Spec == nil {
			return ApplyPlan{}, fmt.Errorf("%s action requires spec", action.Action)
		}
		return ApplyTransportLink(ctx, ipsec, xfrm, *action.Spec, netns)
	case ReconcileActionRepair:
		if action.Spec == nil {
			return ApplyPlan{}, fmt.Errorf("%s action requires spec", action.Action)
		}
		plan, err := ApplyTransportLink(ctx, ipsec, xfrm, *action.Spec, netns)
		if err != nil {
			return plan, err
		}
		if err := InitiateTransportChild(ctx, ipsec, *action.Spec, &plan); err != nil {
			return plan, err
		}
		return plan, nil
	case ReconcileActionUpdate:
		if action.Spec == nil {
			return ApplyPlan{}, fmt.Errorf("%s action requires spec", action.Action)
		}
		if action.Instance != nil && action.Instance.IKEName != "" {
			oldSpec := TransportLinkSpec{
				PeerZone:      action.Instance.PeerZone,
				TransportID:   action.Instance.IKEName,
				InterfaceName: action.Instance.InterfaceName,
				XFRMIfID:      action.Instance.XFRMIfID,
			}
			if _, err := TeardownConnectionOnly(ctx, ipsec, oldSpec); err != nil {
				return ApplyPlan{}, err
			}
		}
		return ApplyTransportLink(ctx, ipsec, xfrm, *action.Spec, netns)
	case ReconcileActionPrepareRotate:
		if action.Spec == nil {
			return ApplyPlan{}, fmt.Errorf("%s action requires spec", action.Action)
		}
		return ApplyStagedConnection(ctx, ipsec, xfrm, *action.Spec, netns)
	case ReconcileActionCommitRotate, ReconcileActionRollbackRotate, ReconcileActionCleanupRotate:
		if action.Spec == nil {
			return ApplyPlan{}, fmt.Errorf("%s action requires spec", action.Action)
		}
		return TeardownTransportLink(ctx, ipsec, xfrm, *action.Spec)
	case ReconcileActionTeardown:
		if action.Spec != nil {
			return TeardownTransportLink(ctx, ipsec, xfrm, *action.Spec)
		}
		if action.Instance == nil {
			return ApplyPlan{}, fmt.Errorf("teardown action requires spec or instance")
		}
		if err := action.Instance.Owner.Validate(*action.Instance); err != nil {
			return ApplyPlan{}, fmt.Errorf("refuse unmanaged teardown: %w", err)
		}
		connSpec := TransportLinkSpec{
			PeerZone:      action.Instance.PeerZone,
			TransportID:   action.Instance.IKEName,
			InterfaceName: action.Instance.InterfaceName,
			XFRMIfID:      action.Instance.XFRMIfID,
		}
		if _, err := TeardownConnectionOnly(ctx, ipsec, connSpec); err != nil {
			return ApplyPlan{}, err
		}
		if action.Instance.StagedIKEName != "" {
			stagedSpec := TransportLinkSpec{
				PeerZone:      action.Instance.PeerZone,
				TransportID:   action.Instance.StagedIKEName,
				InterfaceName: firstNonEmptyString(action.Instance.StagedInterfaceName, action.Instance.InterfaceName),
				XFRMIfID:      firstNonZeroUint32(action.Instance.StagedXFRMIfID, action.Instance.XFRMIfID),
			}
			if _, err := TeardownConnectionOnly(ctx, ipsec, stagedSpec); err != nil {
				return ApplyPlan{}, err
			}
			if err := xfrm.DeleteInterface(ctx, stagedSpec.InterfaceName); err != nil {
				return ApplyPlan{}, fmt.Errorf("delete staged interface: %w", err)
			}
		}
		keySpec := TransportLinkSpec{
			PeerZone:      action.Instance.PeerZone,
			TransportID:   action.Instance.TransportID,
			InterfaceName: action.Instance.InterfaceName,
			XFRMIfID:      action.Instance.XFRMIfID,
		}
		if err := ipsec.UnloadPrivateKey(ctx, keySpec.TransportID); err != nil {
			return ApplyPlan{}, fmt.Errorf("unload private key: %w", err)
		}
		if err := xfrm.DeleteInterface(ctx, action.Instance.InterfaceName); err != nil {
			return ApplyPlan{}, fmt.Errorf("delete interface: %w", err)
		}
		return ApplyPlan{}, nil
	case ReconcileActionAdopt, ReconcileActionNoop:
		return ApplyPlan{}, nil
	default:
		return ApplyPlan{}, fmt.Errorf("unsupported reconcile action %q", action.Action)
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstNonZeroUint32(values ...uint32) uint32 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func (r *ReconcileResult) add(action string, spec *TransportLinkSpec, inst *LinkInstance, reason string) {
	r.Actions = append(r.Actions, ReconcileAction{
		Action:   action,
		Spec:     spec,
		Instance: inst,
		Reason:   reason,
	})
}

func findMatchingSA(states []SAState, spec TransportLinkSpec) SAState {
	childName := ChildSAName(spec)
	for _, state := range states {
		if state.Name == spec.TransportID || state.ChildSA == childName || (spec.XFRMIfID != 0 && state.XFRMIfID == spec.XFRMIfID) {
			return state
		}
	}
	return SAState{}
}

func findInstanceSA(states []SAState, inst LinkInstance) SAState {
	for _, state := range states {
		if state.Name == inst.IKEName || state.ChildSA == inst.ChildSAName {
			return state
		}
		if inst.XFRMIfID != 0 && state.XFRMIfID == inst.XFRMIfID {
			return state
		}
	}
	return SAState{}
}

func firstContactPointForGeneration(spec TransportLinkSpec, generation uint64) (ContactPoint, bool) {
	for _, point := range spec.ContactPoints {
		if point.Generation == generation {
			return point, true
		}
	}
	return firstContactPoint(spec.ContactPoints)
}

func endpointForSpec(spec TransportLinkSpec) string {
	point, ok := firstContactPoint(spec.ContactPoints)
	if !ok {
		return ""
	}
	return contactEndpoint(point)
}

func contactEndpoint(point ContactPoint) string {
	if point.Address != "" {
		return point.Address
	}
	return point.Host
}
