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
)

type LinkInstance struct {
	ID                string
	GroupID           string
	PeerZone          zone.ZonePath
	TransportKind     string
	TransportID       string
	DesiredSpecHash   string
	ActualState       string
	InterfaceName     string
	XFRMIfID          uint32
	IKEName           string
	ChildSAName       string
	Endpoint          string
	SelectedContact   ContactPoint
	RemoteGeneration  uint64
	StagedGeneration  uint64
	RotatePhase       string
	StagedIKEName     string
	StagedChildSAName string
	RotateDeadline    int64
	LastError         string
	FailureCount      int
	BackoffUntil      int64
	LastTransition    int64
	Owner             ResourceOwner
}

type ResourceOwner struct {
	Manager     string
	GroupID     string
	InstanceID  string
	TransportID string
	Token       string
}

type ReconcileInputs struct {
	Desired   []TransportLinkSpec
	Instances map[string]LinkInstance
	SAs       []SAState
	Now       time.Time
	Revoked   map[zone.ZonePath]bool
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
	point, ok := firstContactPoint(spec.ContactPoints)
	if !ok {
		return 0
	}
	return point.Generation
}

func rotateSpec(base TransportLinkSpec, generation uint64) TransportLinkSpec {
	spec := base
	spec.TransportID = RotateConnectionName(base.TransportID, generation)
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
			result.handleRotate(id, spec, existing, in.SAs, now)
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
		if inLinkBackoff(existing, now) {
			result.add(ReconcileActionNoop, &spec, &existing, "apply backoff active")
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
		if sa.Established && inst.ActualState != LinkStateUp {
			inst.ActualState = LinkStateUp
			inst.Endpoint = sa.Endpoint
			inst.LastTransition = now.Unix()
			result.Instances[id] = inst
			result.add(ReconcileActionAdopt, &spec, &inst, "driver state recovered")
			continue
		}
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

func (r *ReconcileResult) handleRotate(id string, spec TransportLinkSpec, existing LinkInstance, sas []SAState, now time.Time) {
	desiredGen := contactGeneration(spec)
	if existing.StagedGeneration != 0 && existing.StagedGeneration != desiredGen {
		inst := existing
		inst.RotatePhase = RotatePhaseCleanup
		r.Instances[id] = inst
		stagedSpec := rotateSpec(spec, existing.StagedGeneration)
		r.add(ReconcileActionCleanupRotate, &stagedSpec, &inst, "stale staged generation")
		return
	}
	if inLinkBackoff(existing, now) {
		r.add(ReconcileActionNoop, &spec, &existing, "rotate backoff active")
		return
	}
	if existing.StagedGeneration == desiredGen {
		stagedSA := findStagedSA(sas, existing)
		if stagedSA.Established {
			inst := existing
			inst.RemoteGeneration = desiredGen
			inst.IKEName = existing.StagedIKEName
			inst.ChildSAName = existing.StagedChildSAName
			if point, ok := firstContactPointForGeneration(spec, desiredGen); ok {
				inst.SelectedContact = point
				inst.Endpoint = contactEndpoint(point)
			}
			inst.DesiredSpecHash = TransportLinkSpecHash(spec)
			inst.StagedGeneration = 0
			inst.StagedIKEName = ""
			inst.StagedChildSAName = ""
			inst.RotatePhase = RotatePhaseCutover
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
			inst.RotatePhase = RotatePhaseRollback
			inst.RotateDeadline = 0
			inst.LastError = "staged sa not established by deadline"
			inst.FailureCount++
			inst.BackoffUntil = now.Add(nextLinkBackoff(BackoffPolicy{}, inst.FailureCount)).Unix()
			inst.LastTransition = now.Unix()
			r.Instances[id] = inst
			stagedSpec := rotateSpec(spec, existing.StagedGeneration)
			r.add(ReconcileActionRollbackRotate, &stagedSpec, &inst, "staged sa deadline exceeded")
			return
		}
		inst := existing
		inst.RotatePhase = RotatePhaseTestingNew
		inst.LastTransition = now.Unix()
		r.Instances[id] = inst
		stagedSpec := rotateSpec(spec, desiredGen)
		r.add(ReconcileActionPrepareRotate, &stagedSpec, &inst, "awaiting staged sa")
		return
	}
	inst := existing
	inst.StagedGeneration = desiredGen
	inst.StagedIKEName = RotateConnectionName(existing.TransportID, desiredGen)
	inst.StagedChildSAName = RotateChildSAName(existing.TransportID, desiredGen)
	inst.RotatePhase = RotatePhasePreparing
	inst.RotateDeadline = now.Add(rotateTimeout()).Unix()
	inst.LastTransition = now.Unix()
	r.Instances[id] = inst
	stagedSpec := rotateSpec(spec, desiredGen)
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
		inst.SelectedContact = ContactPoint{}
		inst.StagedGeneration = 0
		inst.StagedIKEName = ""
		inst.StagedChildSAName = ""
		inst.RotatePhase = RotatePhaseCutover
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

func ApplyReconcileAction(ctx context.Context, ipsec IPsecDriver, xfrm XFRMDriver, action ReconcileAction, netns NetNSSpec) (ApplyPlan, error) {
	switch action.Action {
	case ReconcileActionCreate, ReconcileActionUpdate, ReconcileActionRepair:
		if action.Spec == nil {
			return ApplyPlan{}, fmt.Errorf("%s action requires spec", action.Action)
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
		return TeardownConnectionOnly(ctx, ipsec, *action.Spec)
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
				InterfaceName: action.Instance.InterfaceName,
				XFRMIfID:      action.Instance.XFRMIfID,
			}
			if _, err := TeardownConnectionOnly(ctx, ipsec, stagedSpec); err != nil {
				return ApplyPlan{}, err
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
