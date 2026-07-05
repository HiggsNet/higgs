package main

import (
	"testing"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func TestCloneStateFileDeepCopiesMutableState(t *testing.T) {
	original := stateFile{
		ManagedZone:     "node-a.catofes.",
		RootPrivateKey:  []byte("root-private-key"),
		ZonePrivateKey:  []byte("zone-private-key"),
		Network:         cloneTestNetworkState(),
		SyncPeers:       cloneTestSyncPeers(),
		IPsecPortRecord: &ipsecPortRecordState{Mode: "range", Range: &ipsec.PortRange{From: 4500, To: 4510}, Generation: 7},
		LinkInstances: map[string]linkInstanceState{
			"link-a": {ID: "link-a", Owner: linkOwnerState{Token: "token-a"}},
		},
		IPsecReconcile: &ipsecReconcileState{
			Desired:   []desiredLinkState{{InstanceID: "link-a", Endpoint: "198.51.100.10:4500"}},
			ActualSAs: []linkSAState{{Name: "sa-a"}},
			Actions:   []linkActionState{{Action: "create", InstanceID: "link-a"}},
			Skipped:   []linkSkipState{{GroupID: "group-a", Reason: "revoked"}},
		},
		FirewallReconcile: &firewallReconcileState{
			Instances: map[string]*firewallInstanceReconcileStateEntry{
				"fw-a": {Generation: 3, PolicyHash: "hash-a"},
			},
		},
		BirdInstances: map[string]*BirdInstanceState{
			"net-a": {NetNSName: "net-a", Overlays: []string{"overlay-a"}},
		},
		Admission: &admissionState{Pending: true, PendingReason: "missing_delegation"},
	}

	cloned := cloneStateFile(&original)
	if cloned == nil {
		t.Fatal("clone is nil")
	}

	cloned.RootPrivateKey[0] = 'R'
	cloned.ZonePrivateKey[0] = 'Z'
	cloned.Network.GlobalRoot[0] = 9
	cloned.Network.Zones["node-a.catofes."].Records["endpoint"].Value[0] = 'X'
	cloned.Network.Zones["node-a.catofes."].RecordHistory["endpoint"][0].Value[0] = 'Y'
	cloned.SyncPeers["peer-a"].ObservedGraceAddrs[0].Addr = "203.0.113.2:4500"
	cloned.SyncPeers["peer-a"].RejectedDigests["digest-a"] = rejectedDigestState{Reason: "changed"}
	cloned.IPsecPortRecord.Range.From = 4600
	inst := cloned.LinkInstances["link-a"]
	inst.Owner.Token = "token-b"
	cloned.LinkInstances["link-a"] = inst
	cloned.IPsecReconcile.Desired[0].Endpoint = "198.51.100.20:4500"
	cloned.FirewallReconcile.Instances["fw-a"].PolicyHash = "hash-b"
	cloned.BirdInstances["net-a"].Overlays[0] = "overlay-b"
	cloned.Admission.PendingReason = "changed"

	if string(original.RootPrivateKey) != "root-private-key" {
		t.Fatalf("root private key shared: %q", string(original.RootPrivateKey))
	}
	if string(original.ZonePrivateKey) != "zone-private-key" {
		t.Fatalf("zone private key shared: %q", string(original.ZonePrivateKey))
	}
	if original.Network.GlobalRoot[0] != 1 {
		t.Fatalf("network global root shared: %v", original.Network.GlobalRoot)
	}
	if string(original.Network.Zones["node-a.catofes."].Records["endpoint"].Value) != "endpoint-a" {
		t.Fatalf("record value shared: %q", string(original.Network.Zones["node-a.catofes."].Records["endpoint"].Value))
	}
	if string(original.Network.Zones["node-a.catofes."].RecordHistory["endpoint"][0].Value) != "endpoint-old" {
		t.Fatalf("record history shared: %q", string(original.Network.Zones["node-a.catofes."].RecordHistory["endpoint"][0].Value))
	}
	if original.SyncPeers["peer-a"].ObservedGraceAddrs[0].Addr != "203.0.113.1:4500" {
		t.Fatalf("observed grace addrs shared: %#v", original.SyncPeers["peer-a"].ObservedGraceAddrs)
	}
	if original.SyncPeers["peer-a"].RejectedDigests["digest-a"].Reason != "old" {
		t.Fatalf("rejected digests shared: %#v", original.SyncPeers["peer-a"].RejectedDigests)
	}
	if original.IPsecPortRecord.Range.From != 4500 {
		t.Fatalf("ipsec port range shared: %#v", original.IPsecPortRecord.Range)
	}
	if original.LinkInstances["link-a"].Owner.Token != "token-a" {
		t.Fatalf("link instance owner shared: %#v", original.LinkInstances["link-a"].Owner)
	}
	if original.IPsecReconcile.Desired[0].Endpoint != "198.51.100.10:4500" {
		t.Fatalf("ipsec desired shared: %#v", original.IPsecReconcile.Desired)
	}
	if original.FirewallReconcile.Instances["fw-a"].PolicyHash != "hash-a" {
		t.Fatalf("firewall reconcile shared: %#v", original.FirewallReconcile.Instances["fw-a"])
	}
	if original.BirdInstances["net-a"].Overlays[0] != "overlay-a" {
		t.Fatalf("bird overlays shared: %#v", original.BirdInstances["net-a"].Overlays)
	}
	if original.Admission.PendingReason != "missing_delegation" {
		t.Fatalf("admission shared: %#v", original.Admission)
	}
	if cloned.Network.RecordVerifier == nil || cloned.Network.RecordHasher == nil {
		t.Fatal("clone did not restore network validation hooks")
	}
}

func cloneTestNetworkState() *zone.NetworkState {
	ns := zone.NewNetworkState()
	ns.GlobalRoot = []byte{1, 2, 3}
	ns.Zones["node-a.catofes."] = &zone.ZoneState{
		Path: "node-a.catofes.",
		Records: map[string]*zone.Record{
			"endpoint": {Zone: "node-a.catofes.", Key: "endpoint", Value: []byte("endpoint-a"), Version: 2},
		},
		RecordHistory: map[string][]*zone.Record{
			"endpoint": {{Zone: "node-a.catofes.", Key: "endpoint", Value: []byte("endpoint-old"), Version: 1}},
		},
		Delegations: map[zone.ZonePath]*zone.Delegation{},
		Revocations: map[zone.ZonePath]*zone.DelegationRevocation{},
	}
	configureValidation(ns)
	return ns
}

func cloneTestSyncPeers() map[string]syncPeerState {
	return map[string]syncPeerState{
		"peer-a": {
			ObservedGraceAddrs: []observedGraceAddrState{{Addr: "203.0.113.1:4500"}},
			DatagramStats:      &datagramStats{ChunkFallbacks: 1},
			ObjectPullStats:    &objectPullStats{Attempts: 1},
			RejectedDigests: map[string]rejectedDigestState{
				"digest-a": {Zone: "node-a.catofes.", Reason: "old"},
			},
		},
	}
}
