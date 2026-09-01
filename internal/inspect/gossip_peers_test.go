package inspect

import (
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestBuildGossipPeerDebugViewRejectsUnknownPeer(t *testing.T) {
	common := corestate.View{State: &corestate.VerifiedState{Network: zone.NewNetworkState()}}
	if _, ok := BuildGossipPeerDebugView(common, GossipPeersOptions{}, "ss"); ok {
		t.Fatal("unknown peer produced debug view")
	}
}

func TestBuildGossipPeerViewsProjectOwnersAndLiveDiagnosticsOnce(t *testing.T) {
	now := time.Unix(1700000000, 0)
	peerID := "node-b.catofes."
	common := corestate.View{
		State: &corestate.VerifiedState{ManagedZone: "node-a.catofes.", Network: zone.NewNetworkState()},
		Gossip: &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
			peerID: {
				LastSyncUnix: now.Unix(), DiscoveredEndpoint: "203.0.113.10:33434",
				ObservedEndpoint: "198.51.100.10:33434", ObservedUntilUnix: now.Add(time.Minute).Unix(),
			},
		}},
	}
	options := GossipPeersOptions{
		LocalPeerID: "node-a.catofes.", Now: now,
		Bootstrap:   []PeerBootstrap{{PeerID: peerID, Addr: "bootstrap.example:33434", ResolvedAddr: "192.0.2.10:33434"}},
		Diagnostics: map[string]observability.PeerDiagnostics{peerID: {HintAccepted: 2, ObservedSource: "reply_route"}},
	}

	debug, ok := BuildGossipPeerDebugView(common, options, peerID)
	if !ok {
		t.Fatal("known peer was not projected")
	}
	if debug.Source != "bootstrap" || debug.ConfiguredAddr != "bootstrap.example:33434" || debug.ResolvedAddr != "203.0.113.10:33434" {
		t.Fatalf("debug identity/endpoints = %#v", debug)
	}
	if debug.SyncFlow.HintAccepted != 2 || debug.ObservedStatus == "-" {
		t.Fatalf("debug runtime diagnostics = %#v", debug)
	}

	peers := BuildGossipPeersView(common, options)
	if len(peers.Peers) != 1 || peers.Peers[0].PeerID != peerID || peers.Peers[0].HintAccepted != 2 {
		t.Fatalf("canonical peers = %#v", peers)
	}
}
