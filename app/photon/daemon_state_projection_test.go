package main

import (
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestDaemonStateReadProjectionsAreDetached(t *testing.T) {
	state := &stateFile{
		ManagedZone: "node-a.catofes.",
		Network:     cloneTestNetworkState(),
		SyncPeers:   cloneTestSyncPeers(),
		EndpointACLs: map[string]endpointACL{
			"api": {Name: "api", Selectors: []string{"zone:node-a.catofes."}},
		},
		BirdInstances: map[string]*BirdInstanceState{
			"mesh": {NetNSName: "mesh", Overlays: []string{"main"}},
		},
		LinkInstances: map[string]linkInstanceState{
			"link-a": {ID: "link-a", PeerZone: "peer-a"},
		},
		IPsecReconcile: &ipsecReconcileState{
			DesiredLinks: 1,
			ActualSAs:    []linkSAState{{Name: "sa-a"}},
		},
		FirewallReconcile: &firewallReconcileState{
			Instances: map[string]*firewallInstanceReconcileStateEntry{
				"host": {PolicyHash: "old"},
			},
		},
	}
	store := newTestDaemonStateStore(state)

	status := store.statusProjection()
	if !status.loaded || status.managedZone != state.ManagedZone || status.knownZones != 1 || status.knownPeers != 1 || status.linkInstances != 1 || status.desiredLinks != 1 {
		t.Fatalf("status projection = %+v", status)
	}

	acls, _ := store.endpointACLProjection()
	acls[0].Selectors[0] = "changed"
	againACLs, _ := store.endpointACLProjection()
	if got := againACLs[0].Selectors[0]; got != "zone:node-a.catofes." {
		t.Fatalf("ACL projection mutation leaked: %q", got)
	}

	bird := store.birdStatusProjection()
	bird.instances["mesh"].Overlays[0] = "changed"
	if got := store.birdStatusProjection().instances["mesh"].Overlays[0]; got != "main" {
		t.Fatalf("BIRD projection mutation leaked: %q", got)
	}

	peers := store.peersProjection(&syncConfigFile{}, time.Unix(100, 0), nil)
	peer := peers.peers["peer-a"]
	peer.ObservedGraceAddrs[0].Addr = "changed"
	peer.RejectedDigests["node-a.catofes."] = rejectedDigestState{Reason: "changed"}
	againPeer := store.peersProjection(&syncConfigFile{}, time.Unix(100, 0), nil).peers["peer-a"]
	if got := againPeer.ObservedGraceAddrs[0].Addr; got != "203.0.113.1:4500" {
		t.Fatalf("peer grace projection mutation leaked: %q", got)
	}
	if got := againPeer.RejectedDigests["node-a.catofes."].Reason; got != "old" {
		t.Fatalf("peer rejected digest projection mutation leaked: %q", got)
	}

	links := store.linksStatusProjection(nil, nil)
	links.actualSAs[0].Name = "changed"
	if got := store.linksStatusProjection(nil, nil).actualSAs[0].Name; got != "sa-a" {
		t.Fatalf("link projection mutation leaked: %q", got)
	}

	firewall, _, loaded := store.firewallStatusProjection()
	if !loaded || firewall == nil || firewall.Instances["host"] == nil {
		t.Fatalf("firewall projection = %#v, loaded=%t", firewall, loaded)
	}
	firewall.Instances["host"].PolicyHash = "changed"
	againFirewall, _, _ := store.firewallStatusProjection()
	if got := againFirewall.Instances["host"].PolicyHash; got != "old" {
		t.Fatalf("firewall projection mutation leaked: %q", got)
	}

	response := store.objectPullProjection(&gossip.ObjectPullRequest{
		Type: gossip.ObjectPullRecord, Zone: "node-a.catofes.", Key: "endpoint",
	}, time.Unix(100, 0))
	if response == nil || response.Record == nil || response.Record.Record == nil {
		t.Fatalf("record projection = %#v", response)
	}
	originalRecordValue := string(response.Record.Record.Value)
	response.Record.Record.Value[0] = 'X'
	againResponse := store.objectPullProjection(&gossip.ObjectPullRequest{
		Type: gossip.ObjectPullRecord, Zone: "node-a.catofes.", Key: "endpoint",
	}, time.Unix(100, 0))
	if got := string(againResponse.Record.Record.Value); got != originalRecordValue {
		t.Fatalf("object-pull projection mutation leaked: %q, want %q", got, originalRecordValue)
	}
}

func TestDaemonStateSyncProjectionsAreDetached(t *testing.T) {
	state := &stateFile{
		ManagedZone: "node-a.catofes.",
		Network:     cloneTestNetworkState(),
		SyncPeers:   cloneTestSyncPeers(),
	}
	store := newTestDaemonStateStore(state)
	config := &syncConfigFile{
		PeerID: "local",
		Bootstrap: []syncConfigPeer{
			{ID: "peer-a", Addr: "127.0.0.1:43000"},
		},
	}
	now := time.Unix(100, 0)
	budget := gossip.DefaultMaxMessage

	timer := store.syncTimerProjection(config, now)
	if timer.summary == nil || len(timer.peerStates) != 1 {
		t.Fatalf("timer projection = %+v", timer)
	}
	wantCatalogRoot := append([]byte(nil), timer.summary.CatalogRoot...)
	timer.summary.CatalogRoot[0] ^= 0xff
	peer := timer.peerStates["peer-a"]
	peer.ObservedGraceAddrs[0].Addr = "changed"
	timer.peerStates["peer-a"] = peer

	againTimer := store.syncTimerProjection(config, now)
	if string(againTimer.summary.CatalogRoot) != string(wantCatalogRoot) {
		t.Fatal("catalog summary projection mutation leaked")
	}
	if got := againTimer.peerStates["peer-a"].ObservedGraceAddrs[0].Addr; got != "203.0.113.1:4500" {
		t.Fatalf("timer peer projection mutation leaked: %q", got)
	}

	page, err := store.catalogPageProjection("", budget, "node-a.catofes.")
	if err != nil || page == nil || len(page.Entries) == 0 {
		t.Fatalf("catalog page projection = %#v, err=%v", page, err)
	}
	wantDigestRoot := append([]byte(nil), page.Entries[0].RootHash...)
	page.CatalogRoot[0] ^= 0xff
	page.Entries[0].RootHash[0] ^= 0xff
	againPage, err := store.catalogPageProjection("", budget, "node-a.catofes.")
	if err != nil || string(againPage.CatalogRoot) != string(wantCatalogRoot) || string(againPage.Entries[0].RootHash) != string(wantDigestRoot) {
		t.Fatalf("catalog page projection mutation leaked: %#v, err=%v", againPage, err)
	}

	_, snapshot, err := store.fetchZoneChunkProjection(state.ManagedZone, budget, now)
	if err != nil || snapshot == nil || snapshot.Records["endpoint"] == nil {
		t.Fatalf("zone chunk projection = %#v, err=%v", snapshot, err)
	}
	snapshot.Records["endpoint"].Value[0] = 'X'
	_, againSnapshot, err := store.fetchZoneChunkProjection(state.ManagedZone, budget, now)
	if err != nil || string(againSnapshot.Records["endpoint"].Value) != "endpoint-a" {
		t.Fatalf("zone snapshot projection mutation leaked: %#v, err=%v", againSnapshot, err)
	}

	relay := store.relayProjection(config, now, budget)
	if relay.err != nil || relay.summary == nil {
		t.Fatalf("relay projection summary = %#v, err=%v", relay.summary, relay.err)
	}
	if string(relay.summary.CatalogRoot) != string(wantCatalogRoot) {
		t.Fatalf("relay catalog root = %x, want %x", relay.summary.CatalogRoot, wantCatalogRoot)
	}
	peer = relay.peerStates["peer-a"]
	peer.RejectedDigests["node-a.catofes."] = rejectedDigestState{Reason: "changed"}
	relay.peerStates["peer-a"] = peer
	relay.summary.CatalogRoot[0] ^= 0xff
	againRelay := store.relayProjection(config, now, budget)
	if got := againRelay.peerStates["peer-a"].RejectedDigests["node-a.catofes."].Reason; got != "old" {
		t.Fatalf("relay peer projection mutation leaked: %q", got)
	}
	if string(againRelay.summary.CatalogRoot) != string(wantCatalogRoot) {
		t.Fatal("relay catalog summary projection mutation leaked")
	}
}

func TestDaemonStateProjectionSchemaGuard(t *testing.T) {
	assertStateCloneFields(t, daemonStatusProjection{},
		"loaded", "meta", "managedZone", "knownZones", "knownPeers", "lastSyncUnix",
		"linkInstances", "desiredLinks", "lastLinkError", "lastRoutingError",
		"ipsecLastRunUnix", "routingLastRunUnix")
}
