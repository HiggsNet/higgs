package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func (d *DaemonService) reconcileIPsecLinks(ctx context.Context) error {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return nil
	}
	snapshot, rev, _ := d.snapshotState()
	if snapshot == nil {
		return nil
	}
	groups := append([]ipsec.LinkGroupSpec(nil), d.Sync.App.Config.IPsec.LinkGroups...)
	baseInstances := snapshot.LinkInstances
	if snapshot.ManagedZone.IsRoot() || !snapshot.ManagedZone.Valid() {
		return nil
	}
	now := d.Sync.now()
	plan := ipsec.LinkPlan{}
	if len(groups) > 0 {
		var err error
		plan, err = ipsec.PlanTransportLinks(ctx, snapshot.Network, snapshot.ManagedZone, groups, ipsec.LinkPlannerOptions{
			Now:                 now,
			DNSResolver:         net.DefaultResolver,
			ContactPointQuality: d.buildIPsecContactPointQuality(snapshot, now),
		})
		if err != nil {
			d.recordIPsecReconcileError(rev, now.Unix(), err)
			return err
		}
		plan.Desired = injectIPsecKeyMaterial(snapshot, plan.Desired)
	}
	ipsecDriver, xfrmDriver := d.ipsecDrivers()
	sas, err := ipsecDriver.ListSAs(ctx)
	if err != nil {
		d.recordIPsecReconcileError(rev, now.Unix(), err)
		return fmt.Errorf("list ipsec sas: %w", err)
	}
	instances := linkInstancesToIPsec(snapshot.LinkInstances)
	sas, missingXFRMLinks, err := d.filterSAsWithMissingXFRMLinks(ctx, xfrmDriver, plan.Desired, instances, sas)
	if err != nil {
		d.recordIPsecReconcileError(rev, now.Unix(), err)
		return fmt.Errorf("inspect xfrm links: %w", err)
	}
	markMissingXFRMLinkInstances(instances, missingXFRMLinks, now)
	result := ipsec.ReconcileLinkInstances(ipsec.ReconcileInputs{
		Desired:              plan.Desired,
		Instances:            instances,
		SAs:                  sas,
		Now:                  now,
		Revoked:              revokedLinkPeers(snapshot, now),
		Roles:                plan.Roles,
		GroupBackoff:         groupBackoffMap(groups),
		GroupRotateRetention: groupRotateRetentionMap(groups),
		RotateCutoverReady:   d.ipsecRotateCutoverReady(),
	})
	for _, action := range result.Actions {
		d.logDebug("ipsec", "reconcile_action", ipsecReconcileActionLogFields(action))
		switch action.Action {
		case ipsec.ReconcileActionCreate, ipsec.ReconcileActionUpdate, ipsec.ReconcileActionRepair,
			ipsec.ReconcileActionTeardown, ipsec.ReconcileActionPrepareRotate, ipsec.ReconcileActionCommitRotate,
			ipsec.ReconcileActionRollbackRotate, ipsec.ReconcileActionCleanupRotate:
			netns := netnsForAction(action, groups)
			if _, err := ipsec.ApplyReconcileAction(ctx, ipsecDriver, xfrmDriver, action, netns); err != nil {
				markIPsecActionFailed(result.Instances, action, groupBackoffPolicy(action, groups), now, err)
				if saveErr := d.commitIPsecReconcileResult(rev, baseInstances, now.Unix(), result.Instances, plan.Desired, sas, result.Actions, plan.Skipped, err.Error()); saveErr != nil {
					return fmt.Errorf("save failed ipsec reconcile state after apply error %q: %w", err.Error(), saveErr)
				}
				return err
			}
			markIPsecActionSucceeded(result.Instances, action, now)
		}
	}
	if err := d.commitIPsecReconcileResult(rev, baseInstances, now.Unix(), result.Instances, plan.Desired, sas, result.Actions, plan.Skipped, ""); err != nil {
		return fmt.Errorf("save ipsec reconcile state: %w", err)
	}
	return nil
}

func (d *DaemonService) ipsecRotateCutoverReady() map[string]bool {
	if d == nil || d.health == nil {
		return nil
	}
	return d.health.RotateCutoverReadiness()
}

func ipsecReconcileActionLogFields(action ipsec.ReconcileAction) map[string]any {
	fields := map[string]any{
		"action": action.Action,
		"reason": action.Reason,
	}
	if id := actionInstanceID(action); id != "" {
		fields["instance_id"] = id
	}
	if action.Spec != nil {
		fields["peer"] = action.Spec.PeerZone.String()
		fields["group"] = action.Spec.OverlayID
		fields["transport_id"] = action.Spec.TransportID
		fields["remote_generation"] = action.Spec.Generation
		fields["interface"] = action.Spec.InterfaceName
		if len(action.Spec.ContactPoints) > 0 {
			cp := action.Spec.ContactPoints[0]
			fields["endpoint_address"] = firstNonEmpty(cp.Address, cp.Host)
			fields["endpoint_ike_port"] = cp.IKEPort
			fields["endpoint_natt_port"] = cp.NATTPort
			fields["endpoint_current"] = cp.Current
			fields["endpoint_source"] = cp.Source
		}
	}
	if action.Instance != nil {
		fields["peer"] = action.Instance.PeerZone.String()
		fields["group"] = action.Instance.GroupID
		fields["transport_id"] = action.Instance.TransportID
		fields["remote_generation"] = action.Instance.RemoteGeneration
		fields["staged_generation"] = action.Instance.StagedGeneration
		fields["rotate_phase"] = action.Instance.RotatePhase
		fields["rotate_deadline"] = action.Instance.RotateDeadline
		fields["ike_name"] = action.Instance.IKEName
		fields["staged_ike"] = action.Instance.StagedIKEName
		fields["interface"] = action.Instance.InterfaceName
		fields["staged_interface"] = action.Instance.StagedInterfaceName
	}
	return fields
}

func (d *DaemonService) filterSAsWithMissingXFRMLinks(ctx context.Context, xfrmDriver ipsec.XFRMDriver, desired []ipsec.TransportLinkSpec, instances map[string]ipsec.LinkInstance, sas []ipsec.SAState) ([]ipsec.SAState, map[string]ipsec.TransportLinkSpec, error) {
	if inspector, ok := xfrmDriver.(ipsec.XFRMLinkInspector); ok && len(instances) > 0 {
		return d.filterSAsWithMissingRuntimeLinks(ctx, inspector, desired, instances, sas)
	}
	filter, ok := xfrmDriver.(ipsec.XFRMSAFilter)
	if !ok {
		return sas, nil, nil
	}
	filtered, missing, err := filter.FilterSAsWithMissingLinks(ctx, desired, sas)
	if err != nil {
		return nil, nil, err
	}
	for _, spec := range missing {
		d.logDebug("ipsec", "xfrm_link_missing", map[string]any{
			"instance_id": ipsec.LinkInstanceID(spec),
			"peer":        spec.PeerZone,
			"interface":   spec.InterfaceName,
			"netns":       spec.NetNS,
		})
	}
	return filtered, missing, nil
}

func (d *DaemonService) filterSAsWithMissingRuntimeLinks(ctx context.Context, inspector ipsec.XFRMLinkInspector, desired []ipsec.TransportLinkSpec, instances map[string]ipsec.LinkInstance, sas []ipsec.SAState) ([]ipsec.SAState, map[string]ipsec.TransportLinkSpec, error) {
	if len(desired) == 0 {
		return sas, nil, nil
	}
	missing := make(map[string]ipsec.TransportLinkSpec)
	missingCandidates := make(map[string][]ipsec.TransportLinkSpec)
	for _, spec := range desired {
		id := ipsec.LinkInstanceID(spec)
		candidates := xfrmLinkInspectCandidates(spec, instances[id])
		found := false
		for _, candidate := range candidates {
			state, err := inspector.InspectLink(ctx, candidate)
			if err != nil {
				return nil, nil, err
			}
			if xfrmLinkStateMatchesCandidate(state, candidate) {
				found = true
				break
			}
		}
		if found {
			continue
		}
		missing[id] = spec
		missingCandidates[id] = candidates
		d.logDebug("ipsec", "xfrm_link_missing", map[string]any{
			"instance_id": id,
			"peer":        spec.PeerZone,
			"interface":   spec.InterfaceName,
			"netns":       spec.NetNS,
		})
	}
	if len(missing) == 0 || len(sas) == 0 {
		return sas, missing, nil
	}
	filtered := sas[:0]
	for _, sa := range sas {
		if saMatchesMissingXFRMCandidate(sa, missingCandidates) {
			continue
		}
		filtered = append(filtered, sa)
	}
	return filtered, missing, nil
}

func xfrmLinkStateMatchesCandidate(state ipsec.XFRMLinkState, spec ipsec.TransportLinkSpec) bool {
	if !state.NamespaceExists || !state.InterfaceExists {
		return false
	}
	if !spec.LocalTunnelAddr.IsValid() {
		return true
	}
	for _, prefix := range state.Addresses {
		if prefix.Addr() == spec.LocalTunnelAddr {
			return true
		}
	}
	return false
}

func xfrmLinkInspectCandidates(spec ipsec.TransportLinkSpec, inst ipsec.LinkInstance) []ipsec.TransportLinkSpec {
	candidates := []ipsec.TransportLinkSpec{spec}
	if inst.InterfaceName != "" || inst.XFRMIfID != 0 {
		active := spec
		if inst.InterfaceName != "" {
			active.InterfaceName = inst.InterfaceName
		}
		if inst.XFRMIfID != 0 {
			active.XFRMIfID = inst.XFRMIfID
		}
		active.LocalTunnelAddr = inst.LocalTunnelAddr
		active.PeerTunnelAddr = inst.PeerTunnelAddr
		if !containsXFRMInspectCandidate(candidates, active) {
			candidates = append(candidates, active)
		}
	}
	if inst.StagedInterfaceName != "" || inst.StagedXFRMIfID != 0 {
		staged := spec
		if inst.StagedInterfaceName != "" {
			staged.InterfaceName = inst.StagedInterfaceName
		}
		if inst.StagedXFRMIfID != 0 {
			staged.XFRMIfID = inst.StagedXFRMIfID
		}
		staged.LocalTunnelAddr = inst.StagedLocalTunnelAddr
		staged.PeerTunnelAddr = inst.StagedPeerTunnelAddr
		if !containsXFRMInspectCandidate(candidates, staged) {
			candidates = append(candidates, staged)
		}
	}
	return candidates
}

func containsXFRMInspectCandidate(candidates []ipsec.TransportLinkSpec, candidate ipsec.TransportLinkSpec) bool {
	for _, existing := range candidates {
		if existing.InterfaceName == candidate.InterfaceName && existing.XFRMIfID == candidate.XFRMIfID {
			return true
		}
	}
	return false
}

func saMatchesMissingXFRMCandidate(sa ipsec.SAState, missing map[string][]ipsec.TransportLinkSpec) bool {
	for _, candidates := range missing {
		for _, spec := range candidates {
			if sa.Name == spec.TransportID || sa.ChildSA == ipsec.ChildSAName(spec) || (spec.XFRMIfID != 0 && sa.XFRMIfID == spec.XFRMIfID) {
				return true
			}
		}
	}
	return false
}

func markMissingXFRMLinkInstances(instances map[string]ipsec.LinkInstance, missing map[string]ipsec.TransportLinkSpec, now time.Time) {
	if len(missing) == 0 {
		return
	}
	for id := range missing {
		inst, ok := instances[id]
		if !ok {
			continue
		}
		inst.ActualState = ipsec.LinkStateDegraded
		inst.LastError = "xfrm namespace or interface missing"
		inst.LastTransition = now.Unix()
		instances[id] = inst
	}
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

func (d *DaemonService) commitIPsecReconcileResult(rev uint64, baseInstances map[string]linkInstanceState, unix int64, instances map[string]ipsec.LinkInstance, desired []ipsec.TransportLinkSpec, sas []ipsec.SAState, actions []ipsec.ReconcileAction, skips []ipsec.PlanSkip, lastError string) error {
	if d == nil || d.StateStore == nil {
		return nil
	}
	summary := summarizeIPsecReconcile(rev, unix, desired, sas, actions, skips, lastError)
	summary.Committed = true
	nextInstances := linkInstancesFromIPsec(instances)
	_, committed, err := d.StateStore.CommitIfRevision(rev, func(state *stateFile) error {
		state.LinkInstances = nextInstances
		state.IPsecReconcile = summary
		return nil
	})
	if err != nil {
		return err
	}
	if !committed {
		merged, err := d.commitIPsecReconcileResultByInstance(baseInstances, nextInstances, summary)
		if err != nil {
			return err
		}
		if merged {
			return nil
		}
		summary.Committed = false
		summary.Stale = true
		if err := d.recordStaleIPsecReconcileResult(summary); err != nil {
			return err
		}
		d.ipsecDirty = true
		d.publishStateStoreRuntimeFlags()
		return nil
	}
	committedState, _, _ := d.snapshotState()
	d.installCurrentStateSnapshot(committedState)
	if d.Sync != nil && d.Sync.App != nil {
		return d.Sync.App.SaveState(committedState)
	}
	return saveState(committedState)
}

func (d *DaemonService) commitIPsecReconcileResultByInstance(base, next map[string]linkInstanceState, summary *ipsecReconcileState) (bool, error) {
	if d == nil || d.StateStore == nil || summary == nil {
		return false, nil
	}
	changed := changedLinkInstanceIDs(base, next)
	current, currentRev := d.StateStore.Snapshot()
	if current == nil {
		return false, nil
	}
	if len(changed) == 0 {
		_, committed, err := d.StateStore.CommitIfRevision(currentRev, func(state *stateFile) error {
			state.IPsecReconcile = summary
			return nil
		})
		if err != nil || !committed {
			return false, err
		}
		return true, d.installAndSaveCommittedState()
	}
	if !linkInstanceCommitTokensMatch(base, current.LinkInstances, changed) {
		return false, nil
	}
	_, committed, err := d.StateStore.CommitIfRevision(currentRev, func(state *stateFile) error {
		if state.LinkInstances == nil {
			state.LinkInstances = make(map[string]linkInstanceState)
		}
		for _, id := range changed {
			inst, ok := next[id]
			if !ok {
				delete(state.LinkInstances, id)
				continue
			}
			state.LinkInstances[id] = inst
		}
		state.IPsecReconcile = summary
		return nil
	})
	if err != nil || !committed {
		return false, err
	}
	return true, d.installAndSaveCommittedState()
}

func (d *DaemonService) recordIPsecReconcileError(rev uint64, unix int64, err error) {
	if d == nil || d.StateStore == nil || err == nil {
		return
	}
	_, committed, commitErr := d.StateStore.CommitIfRevision(rev, func(state *stateFile) error {
		reconcile := state.IPsecReconcile
		if reconcile == nil {
			reconcile = &ipsecReconcileState{}
		}
		reconcile.LastRunUnix = unix
		reconcile.SourceRevision = rev
		reconcile.Committed = true
		reconcile.Stale = false
		reconcile.LastError = err.Error()
		state.IPsecReconcile = reconcile
		return nil
	})
	if commitErr != nil {
		d.logWarn("ipsec", "record_reconcile_error_failed", map[string]any{"error": commitErr})
		return
	}
	if !committed {
		if staleErr := d.recordStaleIPsecReconcileResult(&ipsecReconcileState{
			LastRunUnix:    unix,
			SourceRevision: rev,
			Committed:      false,
			Stale:          true,
			LastError:      err.Error(),
		}); staleErr != nil {
			d.logWarn("ipsec", "record_stale_reconcile_error_failed", map[string]any{"error": staleErr})
		}
		d.ipsecDirty = true
		d.publishStateStoreRuntimeFlags()
		return
	}
	committedState, _, _ := d.snapshotState()
	d.installCurrentStateSnapshot(committedState)
	if d.Sync != nil && d.Sync.App != nil {
		if saveErr := d.Sync.App.SaveState(committedState); saveErr != nil {
			d.logWarn("ipsec", "save_reconcile_error_failed", map[string]any{"error": saveErr})
		}
	}
}

func (d *DaemonService) recordStaleIPsecReconcileResult(summary *ipsecReconcileState) error {
	if d == nil || d.StateStore == nil || summary == nil {
		return nil
	}
	current := d.StateStore.Meta().Revision
	_, committed, err := d.StateStore.CommitIfRevision(current, func(state *stateFile) error {
		existing := state.IPsecReconcile
		if existing != nil && existing.LastRunUnix > summary.LastRunUnix {
			return nil
		}
		state.IPsecReconcile = summary
		return nil
	})
	if err != nil {
		return err
	}
	if !committed {
		return nil
	}
	committedState, _, _ := d.snapshotState()
	d.installCurrentStateSnapshot(committedState)
	if d.Sync != nil && d.Sync.App != nil {
		return d.Sync.App.SaveState(committedState)
	}
	return saveState(committedState)
}

func (d *DaemonService) installAndSaveCommittedState() error {
	committedState, _, _ := d.snapshotState()
	d.installCurrentStateSnapshot(committedState)
	if d.Sync != nil && d.Sync.App != nil {
		return d.Sync.App.SaveState(committedState)
	}
	return saveState(committedState)
}

func (d *DaemonService) saveCommittedStateAndInstallIfUnlocked() error {
	committedState, _, _ := d.snapshotState()
	if !d.hasStateLock() {
		d.installCurrentStateSnapshot(committedState)
	}
	if d.Sync != nil && d.Sync.App != nil {
		return d.Sync.App.SaveState(committedState)
	}
	return saveState(committedState)
}

func (d *DaemonService) installAndSaveCommittedStateWithLockTransfer() error {
	committedState, _, _ := d.snapshotState()
	if d.hasStateLock() {
		d.setState(committedState)
	} else {
		d.installCurrentStateSnapshot(committedState)
	}
	if d.Sync != nil && d.Sync.App != nil {
		return d.Sync.App.SaveState(committedState)
	}
	return saveState(committedState)
}

func (d *DaemonService) installCurrentStateSnapshot(state *stateFile) {
	if d == nil || d.Sync == nil || state == nil {
		return
	}
	if state.Network != nil && state.Network.RecordVerifier == nil {
		configureValidation(state.Network)
	}
	d.stateMu.Lock()
	d.Sync.State = state
	d.stateMu.Unlock()
}

func changedLinkInstanceIDs(base, next map[string]linkInstanceState) []string {
	seen := make(map[string]bool, len(base)+len(next))
	var out []string
	for id, baseInst := range base {
		seen[id] = true
		nextInst, ok := next[id]
		if !ok || nextInst != baseInst {
			out = append(out, id)
		}
	}
	for id := range next {
		if !seen[id] {
			out = append(out, id)
		}
	}
	return out
}

func linkInstanceCommitTokensMatch(base, current map[string]linkInstanceState, ids []string) bool {
	for _, id := range ids {
		baseInst, baseOK := base[id]
		currentInst, currentOK := current[id]
		if !baseOK {
			if currentOK {
				return false
			}
			continue
		}
		if !currentOK {
			return false
		}
		baseToken := baseInst.Owner.Token
		currentToken := currentInst.Owner.Token
		if baseToken == "" || currentToken == "" {
			if baseInst != currentInst {
				return false
			}
			continue
		}
		if baseToken != currentToken {
			return false
		}
	}
	return true
}

// buildIPsecContactPointQuality builds a per-peer, per-contact-point quality
// map from the gossip transport's runtime reachability state. This lets the
// IPsec planner deprioritize addresses that are currently in backoff or have
// recent failures, matching the gossip transport's own dialing preferences.
func (d *DaemonService) buildIPsecContactPointQuality(state *stateFile, now time.Time) map[zone.ZonePath]map[string]ipsec.ContactPointQuality {
	if d == nil || d.Sync == nil || d.Sync.Transport == nil || state == nil || state.Network == nil {
		return nil
	}
	transport := d.Sync.Transport
	ns := state.Network
	out := make(map[zone.ZonePath]map[string]ipsec.ContactPointQuality)

	for _, peerID := range transport.KnownPeerIDs() {
		peerPath := zone.ZonePath(peerID)
		if !peerPath.Valid() || peerPath.IsRoot() || peerPath == state.ManagedZone {
			continue
		}
		states := transport.PeerAddrStates(peerID)
		if len(states) == 0 {
			continue
		}
		records, err := ipsec.ExtractNodeRecords(ns, peerPath, now)
		if err != nil || records.Addresses == nil || records.Ports == nil {
			continue
		}
		portAds := ipsec.PortAdvertisements(records.Ports, now)
		if len(portAds) == 0 {
			continue
		}

		inner := make(map[string]ipsec.ContactPointQuality)
		for addrStr, st := range states {
			udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
			if err != nil {
				continue
			}
			ip := udpAddr.IP.String()
			for _, ad := range records.Addresses.Addresses {
				if ad.Address != ip {
					continue
				}
				for _, port := range portAds {
					if !ipsecQualityAddrPortMatches(udpAddr.Port, port) {
						continue
					}
					key := ipsec.ContactPoint{
						AddressID:  ad.ID,
						Address:    ad.Address,
						Generation: port.Generation,
						IKEPort:    contactDialPort(port.IKE),
						NATTPort:   contactDialPort(port.NATT),
					}.Key()
					inner[key] = ipsec.ContactPointQuality{
						Successes:    st.SuccessCount,
						Failures:     st.FailureCount,
						BackoffUntil: st.BackoffUntil,
					}
				}
			}
		}
		if len(inner) > 0 {
			out[peerPath] = inner
		}
	}
	return out
}

func ipsecQualityAddrPortMatches(addrPort int, port ipsec.PortAdvertisement) bool {
	if addrPort <= 0 {
		return false
	}
	return addrPort == int(contactDialPort(port.IKE)) || addrPort == int(contactDialPort(port.NATT))
}

func contactDialPort(binding ipsec.PortBinding) uint16 {
	if binding.Observed != 0 {
		return binding.Observed
	}
	return binding.Advertised
}

func summarizeIPsecReconcile(sourceRev uint64, unix int64, desired []ipsec.TransportLinkSpec, sas []ipsec.SAState, actions []ipsec.ReconcileAction, skips []ipsec.PlanSkip, lastError string) *ipsecReconcileState {
	state := &ipsecReconcileState{
		LastRunUnix:    unix,
		SourceRevision: sourceRev,
		DesiredLinks:   len(desired),
		LastError:      lastError,
	}
	for _, spec := range desired {
		state.Desired = append(state.Desired, desiredLinkState{
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
		})
	}
	for _, sa := range sas {
		state.ActualSAs = append(state.ActualSAs, linkSAState{
			Name:           sa.Name,
			Peer:           sa.Peer,
			ChildSA:        sa.ChildSA,
			IKEState:       sa.IKEState,
			ChildState:     sa.ChildState,
			XFRMIfID:       sa.XFRMIfID,
			ReqID:          sa.ReqID,
			LocalIdentity:  sa.LocalIdentity,
			RemoteIdentity: sa.RemoteIdentity,
			LocalEndpoint:  sa.LocalEndpoint,
			RemoteEndpoint: sa.RemoteEndpoint,
			Endpoint:       sa.Endpoint,
			Established:    sa.Established,
		})
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

func summarizeContactEndpoint(points []ipsec.ContactPoint) string {
	if len(points) == 0 {
		return ""
	}
	if points[0].Address != "" {
		return points[0].Address
	}
	return points[0].Host
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
			ID:                    inst.ID,
			GroupID:               inst.GroupID,
			PeerZone:              inst.PeerZone,
			TransportKind:         inst.TransportKind,
			LinkID:                inst.LinkID,
			PathKey:               inst.PathKey,
			TransportID:           inst.TransportID,
			DesiredSpecHash:       inst.DesiredSpecHash,
			ActualState:           inst.ActualState,
			InterfaceName:         inst.InterfaceName,
			XFRMIfID:              inst.XFRMIfID,
			LocalTunnelAddr:       parseStateAddr(inst.LocalTunnelAddr),
			PeerTunnelAddr:        parseStateAddr(inst.PeerTunnelAddr),
			IKEName:               inst.IKEName,
			ChildSAName:           inst.ChildSAName,
			Endpoint:              inst.Endpoint,
			RemoteGeneration:      inst.RemoteGeneration,
			StagedGeneration:      inst.StagedGeneration,
			RotatePhase:           inst.RotatePhase,
			StagedIKEName:         inst.StagedIKEName,
			StagedChildSAName:     inst.StagedChildSAName,
			StagedInterfaceName:   inst.StagedInterfaceName,
			StagedXFRMIfID:        inst.StagedXFRMIfID,
			StagedLocalTunnelAddr: parseStateAddr(inst.StagedLocalTunnelAddr),
			StagedPeerTunnelAddr:  parseStateAddr(inst.StagedPeerTunnelAddr),
			RotateDeadline:        inst.RotateDeadline,
			LastError:             inst.LastError,
			FailureCount:          inst.FailureCount,
			BackoffUntil:          inst.BackoffUntil,
			LastTransition:        inst.LastTransition,
			Owner: ipsec.ResourceOwner{
				Manager:     inst.Owner.Manager,
				GroupID:     inst.Owner.GroupID,
				InstanceID:  inst.Owner.InstanceID,
				LinkID:      inst.Owner.LinkID,
				TransportID: inst.Owner.TransportID,
				Token:       inst.Owner.Token,
			},
			InitiatorRole:     inst.InitiatorRole,
			TakeoverPhase:     inst.TakeoverPhase,
			TakeoverStartedAt: inst.TakeoverStartedAt,
			TakeoverUntil:     inst.TakeoverUntil,
			LastTakeoverError: inst.LastTakeoverError,
			ObservedInitiator: inst.ObservedInitiator,
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
			ID:                    inst.ID,
			GroupID:               inst.GroupID,
			PeerZone:              inst.PeerZone,
			TransportKind:         inst.TransportKind,
			LinkID:                inst.LinkID,
			PathKey:               inst.PathKey,
			TransportID:           inst.TransportID,
			DesiredSpecHash:       inst.DesiredSpecHash,
			ActualState:           inst.ActualState,
			InterfaceName:         inst.InterfaceName,
			XFRMIfID:              inst.XFRMIfID,
			LocalTunnelAddr:       formatStateAddr(inst.LocalTunnelAddr),
			PeerTunnelAddr:        formatStateAddr(inst.PeerTunnelAddr),
			IKEName:               inst.IKEName,
			ChildSAName:           inst.ChildSAName,
			Endpoint:              inst.Endpoint,
			RemoteGeneration:      inst.RemoteGeneration,
			StagedGeneration:      inst.StagedGeneration,
			RotatePhase:           inst.RotatePhase,
			StagedIKEName:         inst.StagedIKEName,
			StagedChildSAName:     inst.StagedChildSAName,
			StagedInterfaceName:   inst.StagedInterfaceName,
			StagedXFRMIfID:        inst.StagedXFRMIfID,
			StagedLocalTunnelAddr: formatStateAddr(inst.StagedLocalTunnelAddr),
			StagedPeerTunnelAddr:  formatStateAddr(inst.StagedPeerTunnelAddr),
			RotateDeadline:        inst.RotateDeadline,
			LastError:             inst.LastError,
			FailureCount:          inst.FailureCount,
			BackoffUntil:          inst.BackoffUntil,
			LastTransition:        inst.LastTransition,
			Owner: linkOwnerState{
				Manager:     inst.Owner.Manager,
				GroupID:     inst.Owner.GroupID,
				InstanceID:  inst.Owner.InstanceID,
				LinkID:      inst.Owner.LinkID,
				TransportID: inst.Owner.TransportID,
				Token:       inst.Owner.Token,
			},
			InitiatorRole:     inst.InitiatorRole,
			TakeoverPhase:     inst.TakeoverPhase,
			TakeoverStartedAt: inst.TakeoverStartedAt,
			TakeoverUntil:     inst.TakeoverUntil,
			LastTakeoverError: inst.LastTakeoverError,
			ObservedInitiator: inst.ObservedInitiator,
		}
	}
	return out
}

func parseStateAddr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(stripScope(s))
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

func formatStateAddr(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

func revokedLinkPeers(state *stateFile, now time.Time) map[zone.ZonePath]bool {
	// Phase 6.4.5: use the comprehensive revoked peer zone collector that
	// covers both LinkInstances and SyncPeers, so that revocation is detected
	// even for peers that don't have an active link instance yet.
	return collectRevokedPeerZones(state, now)
}

func injectIPsecKeyMaterial(state *stateFile, desired []ipsec.TransportLinkSpec) []ipsec.TransportLinkSpec {
	if state == nil {
		return desired
	}
	localKey := state.IPsecTransportKey
	out := make([]ipsec.TransportLinkSpec, len(desired))
	for i, spec := range desired {
		if localKey != nil && len(localKey.PrivateKey) > 0 {
			spec.LocalPrivateKey = append([]byte(nil), localKey.PrivateKey...)
			spec.LocalPrivateKeyAlgorithm = localKey.Algorithm
		}
		if peerZone := state.Network.Zones[spec.PeerZone]; peerZone != nil {
			if record := peerZone.Records[ipsec.RecordKeyTransportKey]; record != nil {
				if keyRecord, err := ipsec.ParseTransportKeyRecord(record); err == nil {
					if pub, err := ipsec.DecodeTransportPublicKey(*keyRecord); err == nil {
						spec.PeerPublicKey = append([]byte(nil), pub...)
					}
				}
			}
		}
		out[i] = spec
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
	inst = ipsec.MarkLinkApplyFailure(inst, policy, now, err)
	switch action.Action {
	case ipsec.ReconcileActionPrepareRotate, ipsec.ReconcileActionCommitRotate, ipsec.ReconcileActionRollbackRotate, ipsec.ReconcileActionCleanupRotate:
		if inst.RotatePhase != "" {
			inst.LastError = "rotate " + inst.RotatePhase + ": " + inst.LastError
		}
	}
	if inst.InitiatorRole == ipsec.InitiatorRoleSecondaryTakeover {
		inst.TakeoverPhase = ipsec.TakeoverPhaseCooldown
		inst.TakeoverUntil = now.Add(ipsec.TakeoverCooldownDuration(policy)).Unix()
		inst.LastTakeoverError = inst.LastError
	}
	instances[id] = inst
}

func markIPsecActionSucceeded(instances map[string]ipsec.LinkInstance, action ipsec.ReconcileAction, now time.Time) {
	id := actionInstanceID(action)
	if id == "" {
		return
	}
	if action.Action == ipsec.ReconcileActionTeardown {
		delete(instances, id)
		return
	}
	inst, ok := instances[id]
	if !ok {
		return
	}
	inst = ipsec.MarkLinkApplySuccess(inst, now)
	switch action.Action {
	case ipsec.ReconcileActionCreate, ipsec.ReconcileActionUpdate, ipsec.ReconcileActionRepair, ipsec.ReconcileActionPrepareRotate:
		if action.Action == ipsec.ReconcileActionUpdate && inst.InitiatorRole == ipsec.InitiatorRoleSecondaryStandby {
			inst.ActualState = ipsec.LinkStateDown
		} else {
			inst.ActualState = ipsec.LinkStateConnecting
		}
		inst.LastTransition = now.Unix()
		if inst.StagedGeneration != 0 {
			inst.RotatePhase = ipsec.RotatePhaseTestingNew
		}
	case ipsec.ReconcileActionCommitRotate:
		// The staged SA was already established before commit; after tearing
		// down the old connection the link is up and rotation is complete.
		inst.ActualState = ipsec.LinkStateUp
		inst.RotatePhase = ipsec.RotatePhaseIdle
		inst.LastTransition = now.Unix()
	case ipsec.ReconcileActionRollbackRotate:
		inst.ActualState = ipsec.LinkStateConnecting
		inst.StagedGeneration = 0
		inst.StagedIKEName = ""
		inst.StagedChildSAName = ""
		inst.StagedInterfaceName = ""
		inst.StagedXFRMIfID = 0
		inst.StagedLocalTunnelAddr = netip.Addr{}
		inst.StagedPeerTunnelAddr = netip.Addr{}
		inst.RotatePhase = ipsec.RotatePhaseIdle
		inst.RotateDeadline = 0
		inst.LastTransition = now.Unix()
	case ipsec.ReconcileActionCleanupRotate:
		inst.StagedGeneration = 0
		inst.StagedIKEName = ""
		inst.StagedChildSAName = ""
		inst.StagedInterfaceName = ""
		inst.StagedXFRMIfID = 0
		inst.StagedLocalTunnelAddr = netip.Addr{}
		inst.StagedPeerTunnelAddr = netip.Addr{}
		inst.RotatePhase = ipsec.RotatePhaseIdle
		inst.RotateDeadline = 0
	}
	instances[id] = inst
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

func groupBackoffMap(groups []ipsec.LinkGroupSpec) map[string]ipsec.BackoffPolicy {
	out := make(map[string]ipsec.BackoffPolicy, len(groups))
	for _, group := range groups {
		out[group.ID] = group.Reconcile.Backoff
	}
	return out
}

func groupRotateRetentionMap(groups []ipsec.LinkGroupSpec) map[string]int {
	out := make(map[string]int, len(groups))
	for _, group := range groups {
		out[group.ID] = group.Normalized().Reconcile.RotateRetentionSeconds
	}
	return out
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
