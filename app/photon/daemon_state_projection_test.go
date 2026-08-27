package main

import (
	"testing"
	"time"
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

}

func TestDaemonStateProjectionSchemaGuard(t *testing.T) {
	assertStateCloneFields(t, daemonStatusProjection{},
		"loaded", "meta", "managedZone", "knownZones", "knownPeers", "lastSyncUnix",
		"linkInstances", "desiredLinks", "lastLinkError", "lastRoutingError",
		"ipsecLastRunUnix", "routingLastRunUnix")
}
