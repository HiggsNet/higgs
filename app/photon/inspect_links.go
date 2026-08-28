package main

import (
	"context"
	"net"
	"sort"

	"github.com/HiggsNet/photon/internal/inspect"
	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type linkInspectionBuild struct {
	Inspection        inspect.LinkInspection
	Outputs           []photonstate.LinkOutput
	PlannedSpecs      map[string]ipsec.TransportLinkSpec
	ReplannedDesired  int
	ReplanIgnored     bool
	LastDesiredLinks  int
	DesiredPlanSource string
	PlanError         error
}

func buildLinkInspection(rt *Runtime, state *stateFile, health []healthLinkJSON) linkInspectionBuild {
	return buildLinkInspectionWithOptions(rt, state, health, true, "live")
}

// buildStoredLinkInspection reports the last persisted Linux runtime result.
// Unlike buildLinkInspection, it does not recompute a desired plan from a
// legacy aggregate state view.
func buildStoredLinkInspection(rt *Runtime, instances map[string]linkInstanceState, reconcile *ipsecReconcileState, bird map[string]*BirdInstanceState, health []healthLinkJSON) linkInspectionBuild {
	input := inspect.LinkInput{Health: inspectLinkHealth(health)}
	if reconcile != nil {
		input.LastRunUnix = reconcile.LastRunUnix
		input.DesiredLinks = reconcile.DesiredLinks
		input.LastError = reconcile.LastError
		input.LastDesired = inspectDesiredLinks(reconcile.Desired)
		input.ActualSAs = inspectLinkSAs(reconcile.ActualSAs)
		input.Actions = inspectLinkActions(reconcile.Actions)
		input.Skipped = inspectLinkSkips(reconcile.Skipped)
	}
	ids := sortedLinkInstanceIDs(instances)
	input.Instances = make([]inspect.LinkInstance, 0, len(ids))
	for _, id := range ids {
		inst := instances[id]
		birdState, birdNeighbors, birdBestRoutes := debugLinkRoutingState(rt, bird, inst.GroupID)
		input.Instances = append(input.Instances, inspect.BuildLinkInstanceFromRuntime(inst, inspect.LinkRouting{
			BirdState: birdState, BirdNeighbors: birdNeighbors, BirdBestRoutes: birdBestRoutes,
		}))
	}
	lastDesired := lastReconcileDesiredLinks(reconcile)
	return linkInspectionBuild{
		Inspection: inspect.BuildLinks(input), Outputs: buildLinkOutputs(instances, reconcile),
		PlannedSpecs: map[string]ipsec.TransportLinkSpec{}, ReplannedDesired: lastDesired,
		LastDesiredLinks: lastDesired, DesiredPlanSource: "last_reconcile",
	}
}

func linkInspectionControlFromBuild(build linkInspectionBuild) *linkInspectionControl {
	return &linkInspectionControl{
		Inspection:        build.Inspection,
		Outputs:           append([]photonstate.LinkOutput(nil), build.Outputs...),
		ReplannedDesired:  build.ReplannedDesired,
		ReplanIgnored:     build.ReplanIgnored,
		LastDesiredLinks:  build.LastDesiredLinks,
		DesiredPlanSource: build.DesiredPlanSource,
	}
}

func buildLinkInspectionWithOptions(rt *Runtime, state *stateFile, health []healthLinkJSON, allowReplan bool, planSource string) linkInspectionBuild {
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
		birdState, birdNeighbors, birdBestRoutes := debugLinkRoutingState(rt, state.BirdInstances, inst.GroupID)
		input.Instances = append(input.Instances, inspect.BuildLinkInstanceFromRuntime(inst, inspect.LinkRouting{
			BirdState:      birdState,
			BirdNeighbors:  birdNeighbors,
			BirdBestRoutes: birdBestRoutes,
		}))
	}
	lastDesiredLinks := lastReconcileDesiredLinks(reconcile)
	replannedDesired := lastDesiredLinks
	desiredPlanSource := planSource
	var replanIgnored bool
	var planErr error
	if allowReplan {
		var planned []inspect.DesiredLink
		var specs map[string]ipsec.TransportLinkSpec
		planned, specs, planErr = plannedInspectDesiredLinks(rt, state)
		replannedDesired = len(planned)
		desiredPlanSource = "live"
		replanIgnored = shouldIgnorePartialReplan(reconcile, replannedDesired, planErr)
		if replanIgnored {
			desiredPlanSource = "last_reconcile"
		} else {
			input.PlannedDesired = planned
			plannedSpecs = specs
		}
	}
	inspection := inspect.BuildLinks(input)
	if planErr != nil {
		inspection.Summary.DesiredPlanError = planErr.Error()
	}
	return linkInspectionBuild{
		Inspection:        inspection,
		Outputs:           buildLinkOutputs(state.LinkInstances, state.IPsecReconcile),
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

func plannedInspectDesiredLinks(rt *Runtime, state *stateFile) ([]inspect.DesiredLink, map[string]ipsec.TransportLinkSpec, error) {
	specs := map[string]ipsec.TransportLinkSpec{}
	if rt == nil || rt.Config == nil || state == nil || state.Network == nil || state.ManagedZone.IsRoot() || !state.ManagedZone.Valid() || len(rt.Config.IPsec.LinkGroups) == 0 {
		return nil, specs, nil
	}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, rt.Config.IPsec.LinkGroups, ipsec.LinkPlannerOptions{
		Now:           rt.Now(),
		DNSResolver:   net.DefaultResolver,
		ExcludedPeers: peerLifecycleExcludedPeers(state, rt.Now(), rt.Config.PeerLifecycle),
	})
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
		out = append(out, inspect.BuildDesiredLinkFromRuntime(item))
		specs[item.InstanceID] = spec
	}
	return out, specs, nil
}

func inspectDesiredLinks(items []desiredLinkState) []inspect.DesiredLink {
	out := make([]inspect.DesiredLink, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.BuildDesiredLinkFromRuntime(item))
	}
	return out
}

func inspectLinkSAs(items []linkSAState) []inspect.LinkSA {
	out := make([]inspect.LinkSA, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.LinkSA(item))
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
		out = append(out, inspect.BuildLinkActionFromRuntime(item))
	}
	return out
}

func inspectLinkSkips(items []linkSkipState) []inspect.LinkSkip {
	out := make([]inspect.LinkSkip, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.BuildLinkSkipFromRuntime(item))
	}
	return out
}
