package main

import "errors"

func (d *DaemonService) commitRoutingRuntime(revision uint64, birdInstances map[string]*BirdInstanceState, reconcile *routingReconcileState) (uint64, bool, error) {
	if d == nil || d.StateStore == nil {
		return 0, false, errors.New("daemon service is not initialized")
	}
	if d.StateStore.common != nil {
		return d.StateStore.commitComposedRoutingIfRevision(revision, birdInstances, reconcile)
	}
	current, committed := d.StateStore.commitRoutingIfRevision(revision, birdInstances, reconcile)
	if !committed {
		return current, false, nil
	}
	if err := d.saveCommittedMeta(); err != nil {
		return current, false, err
	}
	return current, true, nil
}

func (d *DaemonService) commitIPsecRuntime(revision uint64, transportKey *ipsecTransportKeyState, portRecord *ipsecPortRecordState, linkInstances map[string]linkInstanceState, reconcile *ipsecReconcileState, persistFullLegacy bool) (uint64, bool, error) {
	if d == nil || d.StateStore == nil {
		return 0, false, errors.New("daemon service is not initialized")
	}
	if d.StateStore.common != nil {
		return d.StateStore.commitComposedIPsecIfRevision(revision, transportKey, portRecord, linkInstances, reconcile)
	}
	current, committed := d.StateStore.commitIPsecIfRevision(revision, transportKey, portRecord, linkInstances, reconcile)
	if !committed {
		return current, false, nil
	}
	var err error
	if persistFullLegacy {
		err = d.saveCommittedState()
	} else {
		err = d.saveCommittedMeta()
	}
	if err != nil {
		return current, false, err
	}
	return current, true, nil
}

func (d *DaemonService) commitFirewallRuntime(revision uint64, endpointACLs map[string]endpointACL, reconcile *firewallReconcileState, persistFullLegacy bool) (uint64, bool, error) {
	if d == nil || d.StateStore == nil {
		return 0, false, errors.New("daemon service is not initialized")
	}
	if d.StateStore.common != nil {
		return d.StateStore.commitComposedFirewallIfRevision(revision, endpointACLs, reconcile)
	}
	current, committed := d.StateStore.commitFirewallIfRevision(revision, endpointACLs, reconcile)
	if !committed {
		return current, false, nil
	}
	var err error
	if persistFullLegacy {
		err = d.saveCommittedState()
	} else {
		err = d.saveCommittedMeta()
	}
	if err != nil {
		return current, false, err
	}
	return current, true, nil
}
