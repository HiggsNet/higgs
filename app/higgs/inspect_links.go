package main

import (
	"context"
	"sort"

	"github.com/Catofes/higgs/internal/inspect"
	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

type linkInspectionBuild struct {
	Inspection        inspect.LinkInspection
	PlannedSpecs      map[string]ipsec.TransportLinkSpec
	ReplannedDesired  int
	ReplanIgnored     bool
	LastDesiredLinks  int
	DesiredPlanSource string
	PlanError         error
}

func buildLinkInspection(rt *Runtime, state *stateFile, health []healthLinkJSON) linkInspectionBuild {
	input := inspect.LinkInput{}
	plannedSpecs := map[string]ipsec.TransportLinkSpec{}
	if state == nil {
		return linkInspectionBuild{Inspection: inspect.BuildLinks(input), PlannedSpecs: plannedSpecs}
	}
	reconcile := state.IPsecReconcile
	if reconcile != nil {
		input.LastRunUnix = reconcile.LastRunUnix
		input.DesiredLinks = reconcile.DesiredLinks
		input.LastError = reconcile.LastError
		input.LastDesired = inspectDesiredLinks(reconcile.Desired)
		input.ActualSAs = inspectLinkSAs(reconcile.ActualSAs)
		input.Actions = inspectLinkActions(reconcile.Actions)
		input.Skipped = inspectLinkSkips(reconcile.Skipped)
	}
	input.Health = inspectLinkHealth(health)
	ids := sortedLinkInstanceIDs(state.LinkInstances)
	input.Instances = make([]inspect.LinkInstance, 0, len(ids))
	for _, id := range ids {
		inst := state.LinkInstances[id]
		input.Instances = append(input.Instances, inspectLinkInstance(rt, state, inst))
	}
	planned, specs, planErr := plannedInspectDesiredLinks(rt, state)
	replannedDesired := len(planned)
	lastDesiredLinks := lastReconcileDesiredLinks(reconcile)
	desiredPlanSource := "live"
	replanIgnored := shouldIgnorePartialReplan(reconcile, replannedDesired, planErr)
	if replanIgnored {
		desiredPlanSource = "last_reconcile"
	} else {
		input.PlannedDesired = planned
		plannedSpecs = specs
	}
	inspection := inspect.BuildLinks(input)
	if planErr != nil {
		inspection.Summary.DesiredPlanError = planErr.Error()
	}
	return linkInspectionBuild{
		Inspection:        inspection,
		PlannedSpecs:      plannedSpecs,
		ReplannedDesired:  replannedDesired,
		ReplanIgnored:     replanIgnored,
		LastDesiredLinks:  lastDesiredLinks,
		DesiredPlanSource: desiredPlanSource,
		PlanError:         planErr,
	}
}

func lastReconcileDesiredLinks(reconcile *ipsecReconcileState) int {
	if reconcile == nil {
		return 0
	}
	if len(reconcile.Desired) > 0 {
		return len(reconcile.Desired)
	}
	return reconcile.DesiredLinks
}

func shouldIgnorePartialReplan(reconcile *ipsecReconcileState, replannedDesired int, planErr error) bool {
	if planErr != nil {
		return true
	}
	lastDesiredLinks := lastReconcileDesiredLinks(reconcile)
	return lastDesiredLinks > 0 && replannedDesired < lastDesiredLinks
}

func sortedLinkInstanceIDs(instances map[string]linkInstanceState) []string {
	ids := make([]string, 0, len(instances))
	for id := range instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func inspectLinkInstance(rt *Runtime, state *stateFile, inst linkInstanceState) inspect.LinkInstance {
	birdState, birdNeighbors, birdBestRoutes := debugLinkRoutingState(rt, state.BirdInstances, inst.GroupID)
	return inspect.LinkInstance{
		ID:                  inst.ID,
		GroupID:             inst.GroupID,
		PeerZone:            string(inst.PeerZone),
		TransportKind:       inst.TransportKind,
		LinkID:              inst.LinkID,
		PathKey:             inst.PathKey,
		TransportID:         inst.TransportID,
		DesiredSpecHash:     inst.DesiredSpecHash,
		ActualState:         inst.ActualState,
		InterfaceName:       inst.InterfaceName,
		XFRMIfID:            inst.XFRMIfID,
		IKEName:             inst.IKEName,
		ChildSAName:         inst.ChildSAName,
		Endpoint:            inst.Endpoint,
		RemoteGeneration:    inst.RemoteGeneration,
		StagedGeneration:    inst.StagedGeneration,
		RotatePhase:         inst.RotatePhase,
		StagedIKEName:       inst.StagedIKEName,
		StagedChildSAName:   inst.StagedChildSAName,
		StagedInterfaceName: inst.StagedInterfaceName,
		StagedXFRMIfID:      inst.StagedXFRMIfID,
		RotateDeadline:      inst.RotateDeadline,
		LastError:           inst.LastError,
		FailureCount:        inst.FailureCount,
		BackoffUntil:        inst.BackoffUntil,
		LastTransition:      inst.LastTransition,
		Owner:               inspectLinkOwner(inst.Owner),
		InitiatorRole:       inst.InitiatorRole,
		TakeoverPhase:       inst.TakeoverPhase,
		TakeoverStartedAt:   inst.TakeoverStartedAt,
		TakeoverUntil:       inst.TakeoverUntil,
		LastTakeoverError:   inst.LastTakeoverError,
		ObservedInitiator:   inst.ObservedInitiator,
		Routing: inspect.LinkRouting{
			BirdState:      birdState,
			BirdNeighbors:  birdNeighbors,
			BirdBestRoutes: birdBestRoutes,
		},
	}
}

func plannedInspectDesiredLinks(rt *Runtime, state *stateFile) ([]inspect.DesiredLink, map[string]ipsec.TransportLinkSpec, error) {
	specs := map[string]ipsec.TransportLinkSpec{}
	if rt == nil || rt.Config == nil || state == nil || state.Network == nil || state.ManagedZone.IsRoot() || !state.ManagedZone.Valid() || len(rt.Config.IPsec.LinkGroups) == 0 {
		return nil, specs, nil
	}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, rt.Config.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: rt.Now()})
	if err != nil {
		return nil, specs, err
	}
	desired := injectIPsecKeyMaterial(state, plan.Desired)
	out := make([]inspect.DesiredLink, 0, len(desired))
	for _, spec := range desired {
		item := desiredLinkState{
			InstanceID:      ipsec.LinkInstanceID(spec),
			GroupID:         spec.OverlayID,
			PeerZone:        spec.PeerZone,
			LinkID:          spec.LinkID,
			PathKey:         spec.PathKey,
			TransportID:     spec.TransportID,
			DesiredSpecHash: ipsec.TransportLinkSpecHash(spec),
			InterfaceName:   spec.InterfaceName,
			XFRMIfID:        spec.XFRMIfID,
			Endpoint:        summarizeContactEndpoint(spec.ContactPoints),
			LocalTunnelAddr: ipsec.FormatScopedTunnelAddress(spec.LocalTunnelAddr, spec.InterfaceName, spec.NetNS),
			PeerTunnelAddr:  ipsec.FormatScopedTunnelAddress(spec.PeerTunnelAddr, spec.InterfaceName, spec.NetNS),
		}
		out = append(out, inspectDesiredLink(item))
		specs[item.InstanceID] = spec
	}
	return out, specs, nil
}

func inspectDesiredLinks(items []desiredLinkState) []inspect.DesiredLink {
	out := make([]inspect.DesiredLink, 0, len(items))
	for _, item := range items {
		out = append(out, inspectDesiredLink(item))
	}
	return out
}

func inspectDesiredLink(item desiredLinkState) inspect.DesiredLink {
	return inspect.DesiredLink{
		InstanceID:      item.InstanceID,
		GroupID:         item.GroupID,
		PeerZone:        string(item.PeerZone),
		LinkID:          item.LinkID,
		PathKey:         item.PathKey,
		TransportID:     item.TransportID,
		DesiredSpecHash: item.DesiredSpecHash,
		InterfaceName:   item.InterfaceName,
		XFRMIfID:        item.XFRMIfID,
		Endpoint:        item.Endpoint,
		LocalTunnelAddr: item.LocalTunnelAddr,
		PeerTunnelAddr:  item.PeerTunnelAddr,
	}
}

func inspectLinkSAs(items []linkSAState) []inspect.LinkSA {
	out := make([]inspect.LinkSA, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.LinkSA{
			Name:           item.Name,
			Peer:           item.Peer,
			ChildSA:        item.ChildSA,
			IKEState:       item.IKEState,
			ChildState:     item.ChildState,
			XFRMIfID:       item.XFRMIfID,
			ReqID:          item.ReqID,
			LocalIdentity:  item.LocalIdentity,
			RemoteIdentity: item.RemoteIdentity,
			LocalEndpoint:  item.LocalEndpoint,
			RemoteEndpoint: item.RemoteEndpoint,
			Endpoint:       item.Endpoint,
			Established:    item.Established,
		})
	}
	return out
}

func inspectLinkHealth(items []healthLinkJSON) []inspect.LinkHealth {
	out := make([]inspect.LinkHealth, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.LinkHealth{
			ProbeID:         item.ProbeID,
			InstanceID:      item.InstanceID,
			ProbeRole:       item.ProbeRole,
			InterfaceName:   item.InterfaceName,
			State:           item.State,
			ProbeType:       item.ProbeType,
			Sent:            item.Sent,
			Received:        item.Received,
			Lost:            item.Lost,
			LossRatio:       item.LossRatio,
			LastRTTMs:       item.LastRTTMs,
			EWMARTTMs:       item.EWMARTTMs,
			P50RTTMs:        item.P50RTTMs,
			P95RTTMs:        item.P95RTTMs,
			P99RTTMs:        item.P99RTTMs,
			JitterMs:        item.JitterMs,
			ConsecutiveFail: item.ConsecutiveFail,
			LastError:       item.LastError,
			NextProbeUnix:   item.NextProbeUnix,
			CutoverBlocking: item.CutoverBlocking,
		})
	}
	return out
}

func inspectLinkActions(items []linkActionState) []inspect.LinkAction {
	out := make([]inspect.LinkAction, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.LinkAction{
			Action:     item.Action,
			InstanceID: item.InstanceID,
			GroupID:    item.GroupID,
			PeerZone:   string(item.PeerZone),
			Reason:     item.Reason,
		})
	}
	return out
}

func inspectLinkSkips(items []linkSkipState) []inspect.LinkSkip {
	out := make([]inspect.LinkSkip, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.LinkSkip{
			GroupID: item.GroupID,
			Peer:    string(item.Peer),
			Reason:  item.Reason,
			Detail:  item.Detail,
		})
	}
	return out
}

func inspectLinkOwner(owner linkOwnerState) inspect.LinkOwner {
	return inspect.LinkOwner{
		Manager:     owner.Manager,
		GroupID:     owner.GroupID,
		InstanceID:  owner.InstanceID,
		LinkID:      owner.LinkID,
		TransportID: owner.TransportID,
		Token:       owner.Token,
	}
}

func desiredLinkFromInspect(item inspect.DesiredLink) desiredLinkState {
	return desiredLinkState{
		InstanceID:      item.InstanceID,
		GroupID:         item.GroupID,
		PeerZone:        zone.ZonePath(item.PeerZone),
		LinkID:          item.LinkID,
		PathKey:         item.PathKey,
		TransportID:     item.TransportID,
		DesiredSpecHash: item.DesiredSpecHash,
		InterfaceName:   item.InterfaceName,
		XFRMIfID:        item.XFRMIfID,
		Endpoint:        item.Endpoint,
		LocalTunnelAddr: item.LocalTunnelAddr,
		PeerTunnelAddr:  item.PeerTunnelAddr,
	}
}

func linkSAFromInspect(item *inspect.LinkSA) *linkSAState {
	if item == nil {
		return nil
	}
	return &linkSAState{
		Name:           item.Name,
		Peer:           item.Peer,
		ChildSA:        item.ChildSA,
		IKEState:       item.IKEState,
		ChildState:     item.ChildState,
		XFRMIfID:       item.XFRMIfID,
		ReqID:          item.ReqID,
		LocalIdentity:  item.LocalIdentity,
		RemoteIdentity: item.RemoteIdentity,
		LocalEndpoint:  item.LocalEndpoint,
		RemoteEndpoint: item.RemoteEndpoint,
		Endpoint:       item.Endpoint,
		Established:    item.Established,
	}
}

func healthFromInspect(item *inspect.LinkHealth) *healthLinkJSON {
	if item == nil {
		return nil
	}
	return &healthLinkJSON{
		ProbeID:         item.ProbeID,
		InstanceID:      item.InstanceID,
		ProbeRole:       item.ProbeRole,
		InterfaceName:   item.InterfaceName,
		State:           item.State,
		ProbeType:       item.ProbeType,
		Sent:            item.Sent,
		Received:        item.Received,
		Lost:            item.Lost,
		LossRatio:       item.LossRatio,
		LastRTTMs:       item.LastRTTMs,
		EWMARTTMs:       item.EWMARTTMs,
		P50RTTMs:        item.P50RTTMs,
		P95RTTMs:        item.P95RTTMs,
		P99RTTMs:        item.P99RTTMs,
		JitterMs:        item.JitterMs,
		ConsecutiveFail: item.ConsecutiveFail,
		LastError:       item.LastError,
		NextProbeUnix:   item.NextProbeUnix,
		CutoverBlocking: item.CutoverBlocking,
	}
}
