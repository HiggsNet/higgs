package main

import (
	"testing"
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

	links := store.linksStatusProjection(nil, nil)
	links.actualSAs[0].Name = "changed"
	if got := store.linksStatusProjection(nil, nil).actualSAs[0].Name; got != "sa-a" {
		t.Fatalf("link projection mutation leaked: %q", got)
	}

}

func TestDaemonStateProjectionSchemaGuard(t *testing.T) {
	assertStateCloneFields(t, daemonStatusProjection{},
		"loaded", "meta", "managedZone", "knownZones", "knownPeers", "lastSyncUnix",
		"linkInstances", "desiredLinks", "lastLinkError", "lastRoutingError",
		"ipsecLastRunUnix", "routingLastRunUnix")
}
