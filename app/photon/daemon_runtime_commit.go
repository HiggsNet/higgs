package main

import "errors"

func (d *DaemonService) commitRoutingRuntime(revision uint64, birdInstances map[string]*BirdInstanceState, reconcile *routingReconcileState) (uint64, bool, error) {
	if d == nil || d.StateStore == nil {
		return 0, false, errors.New("daemon service is not initialized")
	}
	return d.StateStore.commitRoutingIfRevision(revision, birdInstances, reconcile)
}

func (d *DaemonService) commitIPsecRuntime(revision uint64, transportKey *ipsecTransportKeyState, portRecord *ipsecPortRecordState, linkInstances map[string]linkInstanceState, reconcile *ipsecReconcileState) (uint64, bool, error) {
	if d == nil || d.StateStore == nil {
		return 0, false, errors.New("daemon service is not initialized")
	}
	return d.StateStore.commitIPsecIfRevision(revision, transportKey, portRecord, linkInstances, reconcile)
}

func (d *DaemonService) commitFirewallRuntime(revision uint64, endpointACLs map[string]endpointACL, reconcile *firewallReconcileState) (uint64, bool, error) {
	if d == nil || d.StateStore == nil {
		return 0, false, errors.New("daemon service is not initialized")
	}
	return d.StateStore.commitFirewallIfRevision(revision, endpointACLs, reconcile)
}
