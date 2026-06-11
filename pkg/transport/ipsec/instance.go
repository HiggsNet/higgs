package ipsec

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	ReconcileActionAdopt    = "adopt"
	ReconcileActionCreate   = "create"
	ReconcileActionUpdate   = "update"
	ReconcileActionRepair   = "repair"
	ReconcileActionTeardown = "teardown"
	ReconcileActionNoop     = "noop"
)

type LinkInstance struct {
	ID              string
	GroupID         string
	PeerZone        zone.ZonePath
	TransportKind   string
	TransportID     string
	DesiredSpecHash string
	ActualState     string
	InterfaceName   string
	XFRMIfID        uint32
	IKEName         string
	ChildSAName     string
	Endpoint        string
	LastError       string
	FailureCount    int
	BackoffUntil    int64
	LastTransition  int64
	Owner           ResourceOwner
}

type ResourceOwner struct {
	Manager     string
	GroupID     string
	InstanceID  string
	TransportID string
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
	return LinkInstance{
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
		},
	}
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
			result.add(ReconcileActionTeardown, &spec, &inst, "peer revoked")
			continue
		}
		specHash := TransportLinkSpecHash(spec)
		sa := findMatchingSA(in.SAs, spec)
		if !exists {
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
		inst.ActualState = LinkStateRemoving
		inst.LastTransition = now.Unix()
		result.Instances[id] = inst
		result.add(ReconcileActionTeardown, nil, &inst, "no longer desired")
	}
	return result
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
	case ReconcileActionTeardown:
		if action.Spec != nil {
			return TeardownTransportLink(ctx, ipsec, xfrm, *action.Spec)
		}
		if action.Instance == nil {
			return ApplyPlan{}, fmt.Errorf("teardown action requires spec or instance")
		}
		spec := TransportLinkSpec{
			PeerZone:      action.Instance.PeerZone,
			TransportID:   action.Instance.TransportID,
			InterfaceName: action.Instance.InterfaceName,
			XFRMIfID:      action.Instance.XFRMIfID,
		}
		return TeardownTransportLink(ctx, ipsec, xfrm, spec)
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

func endpointForSpec(spec TransportLinkSpec) string {
	point, ok := firstContactPoint(spec.ContactPoints)
	if !ok {
		return ""
	}
	if point.Address != "" {
		return point.Address
	}
	return point.Host
}
