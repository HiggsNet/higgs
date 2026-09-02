package main

import (
	"maps"
)

func cloneLinuxRuntimeState(runtime *linuxRuntimeState) *linuxRuntimeState {
	if runtime == nil {
		return &linuxRuntimeState{}
	}
	return &linuxRuntimeState{
		IdentityKeyPath:   runtime.IdentityKeyPath,
		PeerCleanups:      clonePeerCleanups(runtime.PeerCleanups),
		IPsecTransportKey: cloneIPsecTransportKeyState(runtime.IPsecTransportKey),
		IPsecPortRecord:   cloneIPsecPortRecordState(runtime.IPsecPortRecord),
		LinkInstances:     cloneLinkInstances(runtime.LinkInstances),
		IPsecReconcile:    cloneIPsecReconcileState(runtime.IPsecReconcile),
		RoutingReconcile:  cloneRoutingReconcileState(runtime.RoutingReconcile),
		FirewallReconcile: cloneFirewallReconcileState(runtime.FirewallReconcile),
		EndpointACLs:      cloneEndpointACLs(runtime.EndpointACLs),
		BirdInstances:     cloneBirdInstances(runtime.BirdInstances),
		Admission:         cloneAdmissionState(runtime.Admission),
	}
}

func clonePeerCleanups(in map[string]peerLifecycleCleanupState) map[string]peerLifecycleCleanupState {
	if in == nil {
		return nil
	}
	return maps.Clone(in)
}

func cloneRoutingReconcileState(in *routingReconcileState) *routingReconcileState {
	if in == nil {
		return nil
	}
	out := *in
	return &out
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
