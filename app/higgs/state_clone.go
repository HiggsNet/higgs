package main

import (
	"encoding/json"
	"fmt"
)

func cloneStateFile(s *stateFile) *stateFile {
	if s == nil {
		return nil
	}
	// Callers must already own the appropriate state lock, or pass an immutable
	// snapshot/workspace that cannot be mutated concurrently.
	data, err := json.Marshal(s)
	if err != nil {
		panic(fmt.Sprintf("clone state file marshal: %v", err))
	}
	var out stateFile
	if err := json.Unmarshal(data, &out); err != nil {
		panic(fmt.Sprintf("clone state file unmarshal: %v", err))
	}
	if out.Network != nil {
		configureValidation(out.Network)
	}
	return &out
}

// cloneStateFileRootSharingChildren constructs a new immutable state root
// without copying the mutex. Its child values remain shared and must be treated
// as read-only; typed COW mutations replace the specific child they own before
// committing this root.
func cloneStateFileRootSharingChildren(s *stateFile) *stateFile {
	if s == nil {
		return &stateFile{}
	}
	return &stateFile{
		ManagedZone:       s.ManagedZone,
		IdentityKeyPath:   s.IdentityKeyPath,
		RootPrivateKey:    s.RootPrivateKey,
		ZonePrivateKey:    s.ZonePrivateKey,
		Network:           s.Network,
		SyncPeers:         s.SyncPeers,
		IPsecTransportKey: s.IPsecTransportKey,
		IPsecPortRecord:   s.IPsecPortRecord,
		LinkInstances:     s.LinkInstances,
		IPsecReconcile:    s.IPsecReconcile,
		RoutingReconcile:  s.RoutingReconcile,
		FirewallReconcile: s.FirewallReconcile,
		EndpointACLs:      s.EndpointACLs,
		BirdInstances:     s.BirdInstances,
		Admission:         s.Admission,
	}
}

func cloneRoutingReconcileState(in *routingReconcileState) *routingReconcileState {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneSyncPeerState(in syncPeerState) syncPeerState {
	out := in
	if in.ObservedGraceAddrs != nil {
		out.ObservedGraceAddrs = append([]observedGraceAddrState(nil), in.ObservedGraceAddrs...)
	}
	if in.RejectedDigests != nil {
		out.RejectedDigests = make(map[string]rejectedDigestState, len(in.RejectedDigests))
		for key, rejected := range in.RejectedDigests {
			out.RejectedDigests[key] = rejected
		}
	}
	if in.DatagramStats != nil {
		stats := *in.DatagramStats
		out.DatagramStats = &stats
	}
	if in.ObjectPullStats != nil {
		stats := *in.ObjectPullStats
		out.ObjectPullStats = &stats
	}
	return out
}
