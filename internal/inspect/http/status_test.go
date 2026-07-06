package http

import (
	"encoding/json"
	"testing"
)

func TestStatusResponsePreservesObserverSchema(t *testing.T) {
	got := StatusResponse{
		PeerID:            "node-a.catofes.",
		ManagedZone:       "node-a.catofes.",
		ListenAddr:        "127.0.0.1:33434",
		DaemonOnline:      true,
		StateRevision:     3,
		SnapshotTimeUnix:  100,
		KnownZones:        4,
		KnownPeers:        2,
		LinkInstances:     1,
		DesiredLinks:      1,
		LastLinkError:     "ipsec failed",
		LastRoutingError:  "bird failed",
		LastSyncUnix:      90,
		LastReconcileUnix: 95,
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded["peer_id"] != "node-a.catofes." || decoded["daemon_online"] != true {
		t.Fatalf("status fields missing: %#v", decoded)
	}
	if decoded["state_revision"] != float64(3) || decoded["link_instances"] != float64(1) {
		t.Fatalf("numeric fields missing: %#v", decoded)
	}
}

func TestBuildStatusResponseComputesLastReconcile(t *testing.T) {
	got := BuildStatusResponse(StatusInput{
		PeerID:             "node-a.catofes.",
		ManagedZone:        "node-a.catofes.",
		ListenAddr:         "127.0.0.1:33434",
		DaemonOnline:       true,
		StateRevision:      7,
		SnapshotTimeUnix:   100,
		KnownZones:         3,
		KnownPeers:         2,
		LinkInstances:      4,
		DesiredLinks:       5,
		LastSyncUnix:       80,
		IPsecLastRunUnix:   90,
		RoutingLastRunUnix: 95,
	})
	if got.LastReconcileUnix != 95 {
		t.Fatalf("last reconcile = %d, want routing max 95", got.LastReconcileUnix)
	}
	if got.PeerID != "node-a.catofes." || got.StateRevision != 7 || got.LinkInstances != 4 {
		t.Fatalf("status fields not preserved: %#v", got)
	}
}
