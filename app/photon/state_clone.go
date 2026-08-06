package main

import (
	"maps"

	"github.com/Catofes/photon/pkg/core/zone"
)

func cloneStateFile(s *stateFile) *stateFile {
	if s == nil {
		return nil
	}
	// Callers must already own the appropriate state lock, or pass an immutable
	// snapshot/workspace that cannot be mutated concurrently.
	out := &stateFile{
		ManagedZone:       s.ManagedZone,
		IdentityKeyPath:   s.IdentityKeyPath,
		RootPrivateKey:    cloneBytes(s.RootPrivateKey),
		ZonePrivateKey:    cloneBytes(s.ZonePrivateKey),
		Network:           zone.CloneNetworkState(s.Network),
		SyncPeers:         cloneSyncPeers(s.SyncPeers),
		IPsecTransportKey: cloneIPsecTransportKeyState(s.IPsecTransportKey),
		IPsecPortRecord:   cloneIPsecPortRecordState(s.IPsecPortRecord),
		LinkInstances:     cloneLinkInstances(s.LinkInstances),
		IPsecReconcile:    cloneIPsecReconcileState(s.IPsecReconcile),
		RoutingReconcile:  cloneRoutingReconcileState(s.RoutingReconcile),
		FirewallReconcile: cloneFirewallReconcileState(s.FirewallReconcile),
		EndpointACLs:      cloneEndpointACLs(s.EndpointACLs),
		BirdInstances:     cloneBirdInstances(s.BirdInstances),
		Admission:         cloneAdmissionState(s.Admission),
	}
	if out.Network != nil {
		configureValidation(out.Network)
	}
	return out
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
		out.ObservedGraceAddrs = make([]observedGraceAddrState, len(in.ObservedGraceAddrs))
		copy(out.ObservedGraceAddrs, in.ObservedGraceAddrs)
	}
	if in.RejectedDigests != nil {
		out.RejectedDigests = maps.Clone(in.RejectedDigests)
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

func cloneSyncPeers(in map[string]syncPeerState) map[string]syncPeerState {
	if in == nil {
		return nil
	}
	out := make(map[string]syncPeerState, len(in))
	for peerID, peer := range in {
		out[peerID] = cloneSyncPeerState(peer)
	}
	return out
}

func cloneIPsecTransportKeyState(in *ipsecTransportKeyState) *ipsecTransportKeyState {
	if in == nil {
		return nil
	}
	out := *in
	out.PublicKey = cloneBytes(in.PublicKey)
	out.PrivateKey = cloneBytes(in.PrivateKey)
	return &out
}

func cloneIPsecPortRecordState(in *ipsecPortRecordState) *ipsecPortRecordState {
	if in == nil {
		return nil
	}
	out := *in
	if in.Range != nil {
		portRange := *in.Range
		out.Range = &portRange
	}
	return &out
}

func cloneLinkInstances(in map[string]linkInstanceState) map[string]linkInstanceState {
	if in == nil {
		return nil
	}
	return maps.Clone(in)
}

func cloneIPsecReconcileState(in *ipsecReconcileState) *ipsecReconcileState {
	if in == nil {
		return nil
	}
	out := *in
	if in.Desired != nil {
		out.Desired = make([]desiredLinkState, len(in.Desired))
		copy(out.Desired, in.Desired)
	}
	if in.ActualSAs != nil {
		out.ActualSAs = make([]linkSAState, len(in.ActualSAs))
		copy(out.ActualSAs, in.ActualSAs)
	}
	if in.Actions != nil {
		out.Actions = make([]linkActionState, len(in.Actions))
		copy(out.Actions, in.Actions)
	}
	if in.Skipped != nil {
		out.Skipped = make([]linkSkipState, len(in.Skipped))
		copy(out.Skipped, in.Skipped)
	}
	return &out
}

func cloneEndpointACLs(in map[string]endpointACL) map[string]endpointACL {
	if in == nil {
		return nil
	}
	out := make(map[string]endpointACL, len(in))
	for name, acl := range in {
		if acl.Selectors != nil {
			selectors := make([]string, len(acl.Selectors))
			copy(selectors, acl.Selectors)
			acl.Selectors = selectors
		}
		out[name] = acl
	}
	return out
}

func cloneAdmissionState(in *admissionState) *admissionState {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneBytes[T ~byte](in []T) []T {
	if in == nil {
		return nil
	}
	out := make([]T, len(in))
	copy(out, in)
	return out
}
