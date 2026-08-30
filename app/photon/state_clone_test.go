package main

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

var benchmarkStateSnapshot *stateFile

func TestCloneStateFileDeepCopiesMutableState(t *testing.T) {
	original := stateFile{
		ManagedZone:    "node-a.catofes.",
		RootPrivateKey: []byte("root-private-key"),
		ZonePrivateKey: []byte("zone-private-key"),
		Network:        cloneTestNetworkState(),
		SyncPeers:      cloneTestSyncPeers(),
		PeerCleanups: map[string]peerLifecycleCleanupState{
			"peer-a": {LastActiveUnix: 10, CleanupUnix: 20, Reason: peerCleanupReasonOffline},
		},
		IPsecTransportKey: &ipsecTransportKeyState{
			PublicKey:  []byte("transport-public"),
			PrivateKey: []byte("transport-private"),
		},
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
		RoutingReconcile: &routingReconcileState{LastRunUnix: 10, LastError: "old-routing-error"},
		FirewallReconcile: &firewallReconcileState{
			Instances: map[string]*firewallInstanceReconcileStateEntry{
				"fw-a": {Generation: 3, PolicyHash: "hash-a"},
				"nil":  nil,
			},
		},
		EndpointACLs: map[string]endpointACL{
			"api": {Name: "api", Selectors: []string{"zone:catofes."}},
		},
		BirdInstances: map[string]*BirdInstanceState{
			"net-a": {NetNSName: "net-a", Overlays: []string{"overlay-a"}},
			"nil":   nil,
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
	cleanup := cloned.PeerCleanups["peer-a"]
	cleanup.Reason = "changed"
	cloned.PeerCleanups["peer-a"] = cleanup
	cloned.IPsecTransportKey.PublicKey[0] = 'P'
	cloned.IPsecTransportKey.PrivateKey[0] = 'S'
	cloned.IPsecPortRecord.Range.From = 4600
	inst := cloned.LinkInstances["link-a"]
	inst.Owner.Token = "token-b"
	cloned.LinkInstances["link-a"] = inst
	cloned.IPsecReconcile.Desired[0].Endpoint = "198.51.100.20:4500"
	cloned.IPsecReconcile.ActualSAs[0].Name = "sa-b"
	cloned.IPsecReconcile.Actions[0].Action = "delete"
	cloned.IPsecReconcile.Skipped[0].Reason = "changed"
	cloned.RoutingReconcile.LastError = "changed"
	cloned.FirewallReconcile.Instances["fw-a"].PolicyHash = "hash-b"
	cloned.EndpointACLs["api"].Selectors[0] = "zone:changed."
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
	if original.PeerCleanups["peer-a"].Reason != peerCleanupReasonOffline {
		t.Fatalf("peer cleanup map shared: %#v", original.PeerCleanups)
	}
	if string(original.IPsecTransportKey.PublicKey) != "transport-public" ||
		string(original.IPsecTransportKey.PrivateKey) != "transport-private" {
		t.Fatalf("IPsec transport key shared: %#v", original.IPsecTransportKey)
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
	if original.IPsecReconcile.ActualSAs[0].Name != "sa-a" ||
		original.IPsecReconcile.Actions[0].Action != "create" ||
		original.IPsecReconcile.Skipped[0].Reason != "revoked" {
		t.Fatalf("ipsec reconcile slices shared: %#v", original.IPsecReconcile)
	}
	if original.RoutingReconcile.LastError != "old-routing-error" {
		t.Fatalf("routing reconcile shared: %#v", original.RoutingReconcile)
	}
	if original.FirewallReconcile.Instances["fw-a"].PolicyHash != "hash-a" {
		t.Fatalf("firewall reconcile shared: %#v", original.FirewallReconcile.Instances["fw-a"])
	}
	if got := original.EndpointACLs["api"].Selectors[0]; got != "zone:catofes." {
		t.Fatalf("endpoint ACL selectors shared: %q", got)
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
	if value, ok := cloned.FirewallReconcile.Instances["nil"]; !ok || value != nil {
		t.Fatalf("nil firewall instance was not preserved: present=%t value=%#v", ok, value)
	}
	if value, ok := cloned.BirdInstances["nil"]; !ok || value != nil {
		t.Fatalf("nil BIRD instance was not preserved: present=%t value=%#v", ok, value)
	}

	original.EndpointACLs["api"].Selectors[0] = "zone:original-change."
	if got := cloned.EndpointACLs["api"].Selectors[0]; got != "zone:changed." {
		t.Fatalf("original endpoint ACL mutation leaked into clone: %q", got)
	}
}

func TestCloneStateFilePreservesNilAndEmptyShape(t *testing.T) {
	original := &stateFile{
		RootPrivateKey:    []byte{},
		ZonePrivateKey:    nil,
		SyncPeers:         map[string]syncPeerState{},
		PeerCleanups:      map[string]peerLifecycleCleanupState{},
		LinkInstances:     map[string]linkInstanceState{},
		EndpointACLs:      map[string]endpointACL{"empty": {Selectors: []string{}}},
		BirdInstances:     map[string]*BirdInstanceState{},
		IPsecReconcile:    &ipsecReconcileState{Desired: []desiredLinkState{}, ActualSAs: nil, Actions: []linkActionState{}, Skipped: nil},
		FirewallReconcile: &firewallReconcileState{Instances: map[string]*firewallInstanceReconcileStateEntry{}},
	}
	cloned := cloneStateFile(original)
	if cloned.RootPrivateKey == nil || cloned.ZonePrivateKey != nil ||
		cloned.SyncPeers == nil || cloned.PeerCleanups == nil || cloned.LinkInstances == nil || cloned.EndpointACLs == nil ||
		cloned.EndpointACLs["empty"].Selectors == nil || cloned.BirdInstances == nil ||
		cloned.IPsecReconcile.Desired == nil || cloned.IPsecReconcile.ActualSAs != nil ||
		cloned.IPsecReconcile.Actions == nil || cloned.IPsecReconcile.Skipped != nil ||
		cloned.FirewallReconcile.Instances == nil {
		t.Fatalf("nil/empty shape changed: %#v", cloned)
	}
}

func TestCloneStateFileSchemaGuard(t *testing.T) {
	assertStateCloneFields(t, stateFile{}, "ManagedZone", "IdentityKeyPath", "RootPrivateKey", "ZonePrivateKey", "Network", "SyncPeers", "PeerCleanups", "IPsecTransportKey", "IPsecPortRecord", "LinkInstances", "IPsecReconcile", "RoutingReconcile", "FirewallReconcile", "EndpointACLs", "BirdInstances", "Admission")
	assertStateCloneFields(t, peerLifecycleCleanupState{}, "LastActiveUnix", "CleanupUnix", "Reason")
	assertStateCloneFields(t, ipsecTransportKeyState{}, "Kind", "Algorithm", "PublicKey", "PrivateKey", "Fingerprint", "NotBefore", "NotAfter", "UpdatedAt")
	assertStateCloneFields(t, ipsecPortRecordState{}, "Mode", "Range", "Generation", "UpdatedAt")
	assertStateCloneFields(t, linkInstanceState{}, "ID", "GroupID", "PeerZone", "TransportKind", "LinkID", "PathKey", "TransportID", "DesiredSpecHash", "ActualState", "InterfaceName", "XFRMIfID", "LocalTunnelAddr", "PeerTunnelAddr", "IKEName", "ChildSAName", "Endpoint", "RemoteGeneration", "StagedGeneration", "RotatePhase", "StagedIKEName", "StagedChildSAName", "StagedInterfaceName", "StagedXFRMIfID", "StagedLocalTunnelAddr", "StagedPeerTunnelAddr", "RotateDeadline", "LastError", "FailureCount", "BackoffUntil", "LastTransition", "Owner", "InitiatorRole", "TakeoverPhase", "TakeoverStartedAt", "TakeoverUntil", "LastTakeoverError", "ObservedInitiator", "SAAbsentSince", "SAAbsentCount")
	assertStateCloneFields(t, linkOwnerState{}, "Manager", "GroupID", "InstanceID", "LinkID", "TransportID", "Token")
	assertStateCloneFields(t, ipsecReconcileState{}, "LastRunUnix", "SourceRevision", "Committed", "Stale", "DesiredLinks", "Desired", "ActualSAs", "Actions", "Skipped", "LastError")
	assertStateCloneFields(t, desiredLinkState{}, "InstanceID", "GroupID", "PeerZone", "LinkID", "PathKey", "TransportID", "DesiredSpecHash", "InterfaceName", "XFRMIfID", "Endpoint", "LocalTunnelAddr", "PeerTunnelAddr")
	assertStateCloneFields(t, linkSAState{}, "Name", "UniqueID", "Initiator", "InitiatorKnown", "IKEAgeSeconds", "ChildAgeSeconds", "InboundBytes", "InboundPackets", "InboundIdleSecs", "InboundKnown", "Peer", "ChildSA", "IKEState", "ChildState", "XFRMIfID", "ReqID", "LocalIdentity", "RemoteIdentity", "LocalEndpoint", "RemoteEndpoint", "Endpoint", "Established")
	assertStateCloneFields(t, linkActionState{}, "Action", "InstanceID", "GroupID", "PeerZone", "Reason", "SAUniqueID")
	assertStateCloneFields(t, linkSkipState{}, "GroupID", "Peer", "Reason", "Detail")
	assertStateCloneFields(t, routingReconcileState{}, "LastRunUnix", "LastError")
	assertStateCloneFields(t, endpointACL{}, "Name", "Destination", "Scope", "Protocol", "Port", "Selectors")
	assertStateCloneFields(t, firewallReconcileState{}, "Backend", "Instances", "LastRunUnix", "LastError")
	assertStateCloneFields(t, firewallInstanceReconcileStateEntry{}, "Backend", "Generation", "LastRunUnix", "LastError", "PolicyHash", "OwnedObjects")
	assertStateCloneFields(t, BirdInstanceState{}, "NetNSName", "Overlays", "ConfigPath", "ControlSocket", "PIDFile", "RouterID", "Owner", "LastConfigHash", "LastError", "LastExit", "FailureCount", "BackoffUntilUnix", "State")
	assertStateCloneFields(t, admissionState{}, "Pending", "PendingSinceUnix", "AdoptedAtUnix", "LastAdoptionError", "LastBootstrapSyncUnix", "JoinRequestB64", "PendingReason", "PendingReasonDetail")
	assertStateCloneFields(t, syncPeerState{}, "LastSyncUnix", "LastAttemptUnix", "BackoffUntilUnix", "LastRelayUnix", "LastRelayCatalogRootHex", "FailureCount", "LastError", "DiscoveredAddr", "DiscoveredAtUnix", "ObservedAddr", "ObservedFirstSeenUnix", "ObservedLastSeenUnix", "ObservedLastSyncUnix", "ObservedUntilUnix", "ObservedFailureCount", "ObservedGraceAddrs", "RejectedDigests")
	assertStateCloneFields(t, observedGraceAddrState{}, "Addr", "UntilUnix")
	assertStateCloneFields(t, rejectedDigestState{}, "Zone", "Object", "Key", "RootHashHex", "ObjectHashHex", "Reason", "RejectedAtUnix", "UntilUnix")
}

func assertStateCloneFields(t *testing.T, value any, expected ...string) {
	t.Helper()
	typ := reflect.TypeOf(value)
	if typ.NumField() != len(expected) {
		t.Fatalf("%s field count = %d, want %d (%v)", typ, typ.NumField(), len(expected), expected)
	}
	for i, name := range expected {
		if got := typ.Field(i).Name; got != name {
			t.Fatalf("%s field %d = %s, want %s", typ, i, got, name)
		}
	}
}

func BenchmarkCloneStateFile(b *testing.B) {
	state := &stateFile{
		ManagedZone:       "node-a.catofes.",
		RootPrivateKey:    make([]byte, 64),
		ZonePrivateKey:    make([]byte, 64),
		Network:           cloneTestNetworkState(),
		SyncPeers:         cloneTestSyncPeers(),
		IPsecTransportKey: &ipsecTransportKeyState{PublicKey: make([]byte, 32), PrivateKey: make([]byte, 32)},
		IPsecPortRecord:   &ipsecPortRecordState{Range: &ipsec.PortRange{From: 4500, To: 4510}},
		LinkInstances:     map[string]linkInstanceState{"link-a": {ID: "link-a"}},
		IPsecReconcile:    &ipsecReconcileState{Desired: []desiredLinkState{{InstanceID: "link-a"}}, ActualSAs: []linkSAState{{Name: "sa-a"}}, Actions: []linkActionState{{Action: "create"}}, Skipped: []linkSkipState{{Reason: "none"}}},
		RoutingReconcile:  &routingReconcileState{},
		FirewallReconcile: &firewallReconcileState{Instances: map[string]*firewallInstanceReconcileStateEntry{"fw-a": {}}},
		EndpointACLs:      map[string]endpointACL{"api": {Selectors: []string{"zone:catofes."}}},
		BirdInstances:     map[string]*BirdInstanceState{"mesh": {Overlays: []string{"main"}}},
		Admission:         &admissionState{Pending: true},
	}
	zs := state.Network.Zones["node-a.catofes."]
	for i := range 1000 {
		key := string(rune(i + 1))
		zs.Records[key] = &zone.Record{Zone: "node-a.catofes.", Key: key, Value: make([]byte, 128), ValueHash: make([]byte, 32), Signature: make([]byte, 64), Version: 1}
	}

	b.Run("json-baseline", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			data, err := json.Marshal(state)
			if err != nil {
				b.Fatal(err)
			}
			var cloned stateFile
			if err := json.Unmarshal(data, &cloned); err != nil {
				b.Fatal(err)
			}
			if cloned.Network != nil {
				configureValidation(cloned.Network)
			}
			benchmarkStateSnapshot = &cloned
		}
	})
	b.Run("handwritten", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchmarkStateSnapshot = cloneStateFile(state)
		}
	})
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
			RejectedDigests: map[string]rejectedDigestState{
				"digest-a": {Zone: "node-a.catofes.", RootHashHex: "01", Reason: "old"},
			},
		},
	}
}
