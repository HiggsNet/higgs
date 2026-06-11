package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func (d *DaemonService) reconcileIPsecLinks(ctx context.Context) error {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil || d.Sync.State == nil {
		return nil
	}
	groups := d.Sync.App.Config.IPsec.LinkGroups
	if len(groups) == 0 || d.Sync.State.ManagedZone.IsRoot() || !d.Sync.State.ManagedZone.Valid() {
		return nil
	}
	now := d.Sync.now()
	plan, err := ipsec.PlanTransportLinks(ctx, d.Sync.State.Network, d.Sync.State.ManagedZone, groups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		d.recordIPsecReconcileError(now.Unix(), err)
		return err
	}
	ipsecDriver, xfrmDriver := d.ipsecDrivers()
	sas, err := ipsecDriver.ListSAs(ctx)
	if err != nil {
		d.recordIPsecReconcileError(now.Unix(), err)
		return fmt.Errorf("list ipsec sas: %w", err)
	}
	result := ipsec.ReconcileLinkInstances(ipsec.ReconcileInputs{
		Desired:   plan.Desired,
		Instances: linkInstancesToIPsec(d.Sync.State.LinkInstances),
		SAs:       sas,
		Now:       now,
		Revoked:   revokedLinkPeers(d.Sync.State, now),
	})
	for _, action := range result.Actions {
		switch action.Action {
		case ipsec.ReconcileActionCreate, ipsec.ReconcileActionUpdate, ipsec.ReconcileActionRepair, ipsec.ReconcileActionTeardown:
			netns := netnsForAction(action, groups)
			if _, err := ipsec.ApplyReconcileAction(ctx, ipsecDriver, xfrmDriver, action, netns); err != nil {
				markIPsecActionFailed(result.Instances, action, groupBackoffPolicy(action, groups), now, err)
				d.Sync.State.LinkInstances = linkInstancesFromIPsec(result.Instances)
				d.Sync.State.IPsecReconcile = summarizeIPsecReconcile(now.Unix(), len(plan.Desired), result.Actions, plan.Skipped, err.Error())
				if saveErr := d.Sync.saveState(); saveErr != nil {
					return fmt.Errorf("save failed ipsec reconcile state after apply error %q: %w", err.Error(), saveErr)
				}
				d.recordIPsecReconcileError(now.Unix(), err)
				return err
			}
			markIPsecActionSucceeded(result.Instances, action, now)
		}
	}
	d.Sync.State.LinkInstances = linkInstancesFromIPsec(result.Instances)
	d.Sync.State.IPsecReconcile = summarizeIPsecReconcile(now.Unix(), len(plan.Desired), result.Actions, plan.Skipped, "")
	if err := d.Sync.saveState(); err != nil {
		return fmt.Errorf("save ipsec reconcile state: %w", err)
	}
	return nil
}

func (d *DaemonService) ipsecDrivers() (ipsec.IPsecDriver, ipsec.XFRMDriver) {
	var dryRun *ipsec.DryRunDriver
	ipsecDriver := d.IPsecDriver
	xfrmDriver := d.XFRMDriver
	if ipsecDriver == nil || xfrmDriver == nil {
		dryRun = &ipsec.DryRunDriver{}
	}
	if ipsecDriver == nil {
		ipsecDriver = dryRun
	}
	if xfrmDriver == nil {
		xfrmDriver = dryRun
	}
	return ipsecDriver, xfrmDriver
}

func (d *DaemonService) recordIPsecReconcileError(unix int64, err error) {
	if d == nil || d.Sync == nil || d.Sync.State == nil || err == nil {
		return
	}
	state := d.Sync.State.IPsecReconcile
	if state == nil {
		state = &ipsecReconcileState{}
	}
	state.LastRunUnix = unix
	state.LastError = err.Error()
	d.Sync.State.IPsecReconcile = state
}

func summarizeIPsecReconcile(unix int64, desired int, actions []ipsec.ReconcileAction, skips []ipsec.PlanSkip, lastError string) *ipsecReconcileState {
	state := &ipsecReconcileState{
		LastRunUnix:  unix,
		DesiredLinks: desired,
		LastError:    lastError,
	}
	for _, action := range actions {
		item := linkActionState{Action: action.Action, Reason: action.Reason}
		if action.Instance != nil {
			item.InstanceID = action.Instance.ID
			item.GroupID = action.Instance.GroupID
			item.PeerZone = action.Instance.PeerZone
		}
		if action.Spec != nil {
			item.InstanceID = ipsec.LinkInstanceID(*action.Spec)
			item.GroupID = action.Spec.OverlayID
			item.PeerZone = action.Spec.PeerZone
		}
		state.Actions = append(state.Actions, item)
	}
	for _, skip := range skips {
		state.Skipped = append(state.Skipped, linkSkipState{
			GroupID: skip.GroupID,
			Peer:    skip.Peer,
			Reason:  skip.Reason,
			Detail:  skip.Detail,
		})
	}
	return state
}

func desiredIPsecLinks(state *stateFile) int {
	if state == nil || state.IPsecReconcile == nil {
		return 0
	}
	return state.IPsecReconcile.DesiredLinks
}

func lastIPsecReconcileError(state *stateFile) string {
	if state == nil || state.IPsecReconcile == nil {
		return ""
	}
	return state.IPsecReconcile.LastError
}

func linkInstancesToIPsec(in map[string]linkInstanceState) map[string]ipsec.LinkInstance {
	out := make(map[string]ipsec.LinkInstance, len(in))
	for id, inst := range in {
		out[id] = ipsec.LinkInstance{
			ID:              inst.ID,
			GroupID:         inst.GroupID,
			PeerZone:        inst.PeerZone,
			TransportKind:   inst.TransportKind,
			TransportID:     inst.TransportID,
			DesiredSpecHash: inst.DesiredSpecHash,
			ActualState:     inst.ActualState,
			InterfaceName:   inst.InterfaceName,
			XFRMIfID:        inst.XFRMIfID,
			IKEName:         inst.IKEName,
			ChildSAName:     inst.ChildSAName,
			Endpoint:        inst.Endpoint,
			LastError:       inst.LastError,
			FailureCount:    inst.FailureCount,
			BackoffUntil:    inst.BackoffUntil,
			LastTransition:  inst.LastTransition,
			Owner: ipsec.ResourceOwner{
				Manager:     inst.Owner.Manager,
				GroupID:     inst.Owner.GroupID,
				InstanceID:  inst.Owner.InstanceID,
				TransportID: inst.Owner.TransportID,
			},
		}
	}
	return out
}

func linkInstancesFromIPsec(in map[string]ipsec.LinkInstance) map[string]linkInstanceState {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]linkInstanceState, len(in))
	for id, inst := range in {
		out[id] = linkInstanceState{
			ID:              inst.ID,
			GroupID:         inst.GroupID,
			PeerZone:        inst.PeerZone,
			TransportKind:   inst.TransportKind,
			TransportID:     inst.TransportID,
			DesiredSpecHash: inst.DesiredSpecHash,
			ActualState:     inst.ActualState,
			InterfaceName:   inst.InterfaceName,
			XFRMIfID:        inst.XFRMIfID,
			IKEName:         inst.IKEName,
			ChildSAName:     inst.ChildSAName,
			Endpoint:        inst.Endpoint,
			LastError:       inst.LastError,
			FailureCount:    inst.FailureCount,
			BackoffUntil:    inst.BackoffUntil,
			LastTransition:  inst.LastTransition,
			Owner: linkOwnerState{
				Manager:     inst.Owner.Manager,
				GroupID:     inst.Owner.GroupID,
				InstanceID:  inst.Owner.InstanceID,
				TransportID: inst.Owner.TransportID,
			},
		}
	}
	return out
}

func revokedLinkPeers(state *stateFile, now time.Time) map[zone.ZonePath]bool {
	out := map[zone.ZonePath]bool{}
	if state == nil || state.Network == nil {
		return out
	}
	for _, inst := range state.LinkInstances {
		if state.Network.IsZoneRevoked(inst.PeerZone, now) {
			out[inst.PeerZone] = true
		}
	}
	return out
}

func netnsForAction(action ipsec.ReconcileAction, groups []ipsec.LinkGroupSpec) ipsec.NetNSSpec {
	groupID := ""
	if action.Spec != nil {
		groupID = action.Spec.OverlayID
	} else if action.Instance != nil {
		groupID = action.Instance.GroupID
	}
	for _, group := range groups {
		if group.ID == groupID {
			return group.NetNS
		}
	}
	return ipsec.NetNSSpec{}
}

func markIPsecActionFailed(instances map[string]ipsec.LinkInstance, action ipsec.ReconcileAction, policy ipsec.BackoffPolicy, now time.Time, err error) {
	id := actionInstanceID(action)
	if id == "" {
		return
	}
	inst, ok := instances[id]
	if !ok {
		if action.Instance != nil {
			inst = *action.Instance
		} else if action.Spec != nil {
			inst = ipsec.NewLinkInstance(*action.Spec, ipsec.LinkStateError, now)
		} else {
			return
		}
	}
	instances[id] = ipsec.MarkLinkApplyFailure(inst, policy, now, err)
}

func markIPsecActionSucceeded(instances map[string]ipsec.LinkInstance, action ipsec.ReconcileAction, now time.Time) {
	id := actionInstanceID(action)
	if id == "" {
		return
	}
	inst, ok := instances[id]
	if !ok {
		return
	}
	instances[id] = ipsec.MarkLinkApplySuccess(inst, now)
}

func actionInstanceID(action ipsec.ReconcileAction) string {
	if action.Instance != nil && action.Instance.ID != "" {
		return action.Instance.ID
	}
	if action.Spec != nil {
		return ipsec.LinkInstanceID(*action.Spec)
	}
	return ""
}

func groupBackoffPolicy(action ipsec.ReconcileAction, groups []ipsec.LinkGroupSpec) ipsec.BackoffPolicy {
	groupID := ""
	if action.Spec != nil {
		groupID = action.Spec.OverlayID
	} else if action.Instance != nil {
		groupID = action.Instance.GroupID
	}
	for _, group := range groups {
		if group.ID == groupID {
			return group.Reconcile.Backoff
		}
	}
	return ipsec.BackoffPolicy{}
}
