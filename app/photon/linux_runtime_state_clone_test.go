package main

import (
	"reflect"
	"testing"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestCloneLinuxRuntimeStateDeepCopiesMutableFields(t *testing.T) {
	original := &linuxRuntimeState{
		IdentityKeyPath: "/keys/identity.json",
		PeerCleanups: map[string]peerLifecycleCleanupState{
			"peer-a": {LastActiveUnix: 10, CleanupUnix: 20, Reason: peerCleanupReasonOffline},
		},
		IPsecTransportKey: &ipsecTransportKeyState{PublicKey: []byte("public"), PrivateKey: []byte("private")},
		IPsecPortRecord:   &ipsecPortRecordState{Range: &ipsec.PortRange{From: 4500, To: 4510}},
		LinkInstances:     map[string]linkInstanceState{"link-a": {ID: "link-a", Owner: linkOwnerState{Token: "token-a"}}},
		IPsecReconcile: &ipsecReconcileState{
			Desired:   []desiredLinkState{{InstanceID: "link-a", Endpoint: "198.51.100.10:4500"}},
			ActualSAs: []linkSAState{{Name: "sa-a"}},
			Actions:   []linkActionState{{Action: "create"}},
			Skipped:   []linkSkipState{{Reason: "revoked"}},
		},
		RoutingReconcile: &routingReconcileState{LastError: "routing-error"},
		FirewallReconcile: &firewallReconcileState{Instances: map[string]*firewallInstanceReconcileStateEntry{
			"fw-a": {PolicyHash: "hash-a"},
			"nil":  nil,
		}},
		EndpointACLs: map[string]endpointACL{"api": {Selectors: []string{"zone:catofes."}}},
		BirdInstances: map[string]*BirdInstanceState{
			"mesh": {Overlays: []string{"main"}},
			"nil":  nil,
		},
		Admission: &admissionState{Pending: true, PendingReason: "missing_delegation"},
	}

	cloned := cloneLinuxRuntimeState(original)
	cloned.PeerCleanups["peer-a"] = peerLifecycleCleanupState{Reason: "changed"}
	cloned.IPsecTransportKey.PublicKey[0] = 'P'
	cloned.IPsecTransportKey.PrivateKey[0] = 'S'
	cloned.IPsecPortRecord.Range.From = 4600
	link := cloned.LinkInstances["link-a"]
	link.Owner.Token = "token-b"
	cloned.LinkInstances["link-a"] = link
	cloned.IPsecReconcile.Desired[0].Endpoint = "198.51.100.20:4500"
	cloned.IPsecReconcile.ActualSAs[0].Name = "sa-b"
	cloned.IPsecReconcile.Actions[0].Action = "delete"
	cloned.IPsecReconcile.Skipped[0].Reason = "changed"
	cloned.RoutingReconcile.LastError = "changed"
	cloned.FirewallReconcile.Instances["fw-a"].PolicyHash = "hash-b"
	cloned.EndpointACLs["api"].Selectors[0] = "zone:changed."
	cloned.BirdInstances["mesh"].Overlays[0] = "changed"
	cloned.Admission.PendingReason = "changed"

	if original.PeerCleanups["peer-a"].Reason != peerCleanupReasonOffline ||
		string(original.IPsecTransportKey.PublicKey) != "public" ||
		string(original.IPsecTransportKey.PrivateKey) != "private" ||
		original.IPsecPortRecord.Range.From != 4500 ||
		original.LinkInstances["link-a"].Owner.Token != "token-a" {
		t.Fatalf("top-level runtime fields share mutable state: %#v", original)
	}
	if original.IPsecReconcile.Desired[0].Endpoint != "198.51.100.10:4500" ||
		original.IPsecReconcile.ActualSAs[0].Name != "sa-a" ||
		original.IPsecReconcile.Actions[0].Action != "create" ||
		original.IPsecReconcile.Skipped[0].Reason != "revoked" {
		t.Fatalf("IPsec reconcile slices share mutable state: %#v", original.IPsecReconcile)
	}
	if original.RoutingReconcile.LastError != "routing-error" ||
		original.FirewallReconcile.Instances["fw-a"].PolicyHash != "hash-a" ||
		original.EndpointACLs["api"].Selectors[0] != "zone:catofes." ||
		original.BirdInstances["mesh"].Overlays[0] != "main" ||
		original.Admission.PendingReason != "missing_delegation" {
		t.Fatalf("nested runtime fields share mutable state: %#v", original)
	}
	if cloned.FirewallReconcile.Instances["nil"] != nil || cloned.BirdInstances["nil"] != nil {
		t.Fatalf("nil map entries were not preserved: firewall=%#v bird=%#v", cloned.FirewallReconcile.Instances, cloned.BirdInstances)
	}
}

func TestCloneLinuxRuntimeStatePreservesNilAndEmptyShape(t *testing.T) {
	original := &linuxRuntimeState{
		PeerCleanups:      map[string]peerLifecycleCleanupState{},
		LinkInstances:     map[string]linkInstanceState{},
		EndpointACLs:      map[string]endpointACL{"empty": {Selectors: []string{}}},
		BirdInstances:     map[string]*BirdInstanceState{},
		IPsecReconcile:    &ipsecReconcileState{Desired: []desiredLinkState{}, Actions: []linkActionState{}},
		FirewallReconcile: &firewallReconcileState{Instances: map[string]*firewallInstanceReconcileStateEntry{}},
	}
	cloned := cloneLinuxRuntimeState(original)
	if cloned.PeerCleanups == nil || cloned.LinkInstances == nil || cloned.EndpointACLs == nil ||
		cloned.EndpointACLs["empty"].Selectors == nil || cloned.BirdInstances == nil ||
		cloned.IPsecReconcile.Desired == nil || cloned.IPsecReconcile.ActualSAs != nil ||
		cloned.IPsecReconcile.Actions == nil || cloned.IPsecReconcile.Skipped != nil ||
		cloned.FirewallReconcile.Instances == nil {
		t.Fatalf("nil/empty shape changed: %#v", cloned)
	}
	if got := cloneLinuxRuntimeState(nil); got == nil || !reflect.DeepEqual(got, &linuxRuntimeState{}) {
		t.Fatalf("nil runtime clone = %#v, want empty runtime", got)
	}
}

func TestCloneLinuxRuntimeStateSchemaGuard(t *testing.T) {
	want := []string{
		"IdentityKeyPath", "PeerCleanups", "IPsecTransportKey", "IPsecPortRecord", "LinkInstances",
		"IPsecReconcile", "RoutingReconcile", "FirewallReconcile", "EndpointACLs", "BirdInstances", "Admission",
	}
	typ := reflect.TypeOf(linuxRuntimeState{})
	if typ.NumField() != len(want) {
		t.Fatalf("linuxRuntimeState field count = %d, want %d (%v)", typ.NumField(), len(want), want)
	}
	for index, name := range want {
		if got := typ.Field(index).Name; got != name {
			t.Fatalf("linuxRuntimeState field %d = %s, want %s", index, got, name)
		}
	}
}
