package main

import (
	"bytes"
	"testing"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestComposeLinuxStateViewSeparatesOwnersAndDetaches(t *testing.T) {
	rt, _ := buildIPAMTestRuntime(t)
	legacy, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	candidate, _, err := projectLegacyCommonState(legacy, rt.Config.TrustedRootPublicKey)
	if err != nil {
		t.Fatalf("projectLegacyCommonState: %v", err)
	}
	common := corestate.NewStoreWithCheckpoint(candidate.Verified, candidate.Gossip, nil)
	commonView := common.ReadView()
	originalIdentityKey := append([]byte(nil), commonView.State.IdentityPrivateKey...)
	commonView.Gossip.Peers["peer.catofes."] = corestate.PeerCheckpoint{
		BackoffUntilUnix: 42,
		LastFailure:      &corestate.PeerFailure{Code: corestate.PeerFailureTransport, Message: "offline"},
		ObservedGraceEndpoints: []corestate.ObservedGraceEndpoint{{
			Endpoint: "192.0.2.2:2022", UntilUnix: 55,
		}},
		RejectedObjects: map[zone.ZonePath]corestate.RejectedObject{
			"bad.catofes.": {RootHash: []byte{1, 2, 3}, Reason: "invalid_snapshot", UpdatedUnix: 9},
		},
	}
	runtime := &linuxRuntimeState{
		IdentityKeyPath: "/run/photon/identity.key",
		PeerCleanups: map[string]peerLifecycleCleanupState{
			"peer.catofes.": {CleanupUnix: 7, Reason: "inactive"},
		},
		EndpointACLs: map[string]endpointACL{"admin": {Name: "admin"}},
	}

	view := composeLinuxStateView(commonView, runtime)
	if view.ManagedZone != commonView.State.ManagedZone || view.IdentityKeyPath != runtime.IdentityKeyPath {
		t.Fatalf("composed ownership mismatch: managed=%q identity_path=%q", view.ManagedZone, view.IdentityKeyPath)
	}
	peer := view.SyncPeers["peer.catofes."]
	if peer.BackoffUntilUnix != 42 || peer.LastError != "offline" || len(peer.ObservedGraceAddrs) != 1 {
		t.Fatalf("checkpoint read view = %+v", peer)
	}
	if rejected := peer.RejectedDigests["bad.catofes."]; rejected.RootHashHex != "010203" || rejected.Reason != "invalid_snapshot" {
		t.Fatalf("rejected read view = %+v", rejected)
	}

	view.ManagedZone = "mutated.example."
	view.ZonePrivateKey[0] ^= 0xff
	view.Network.Zones[zone.RootZone].Records["detached"] = nil
	mutatedPeer := view.SyncPeers["peer.catofes."]
	mutatedPeer.ObservedGraceAddrs[0].Addr = "mutated"
	view.SyncPeers["peer.catofes."] = mutatedPeer
	cleanup := view.PeerCleanups["peer.catofes."]
	cleanup.Reason = "mutated"
	view.PeerCleanups["peer.catofes."] = cleanup
	view.EndpointACLs["admin"] = endpointACL{Name: "mutated"}

	after := common.ReadView()
	if after.State.ManagedZone != commonView.State.ManagedZone || bytes.Equal(view.ZonePrivateKey, after.State.IdentityPrivateKey) {
		t.Fatalf("common state was not detached")
	}
	if _, ok := after.State.Network.Zones[zone.RootZone].Records["detached"]; ok {
		t.Fatalf("composed network mutation escaped into common store")
	}
	if got := commonView.Gossip.Peers["peer.catofes."].ObservedGraceEndpoints[0].Endpoint; got != "192.0.2.2:2022" {
		t.Fatalf("checkpoint mutation escaped: %q", got)
	}
	if got := runtime.PeerCleanups["peer.catofes."].Reason; got != "inactive" {
		t.Fatalf("runtime cleanup mutation escaped: %q", got)
	}
	if got := runtime.EndpointACLs["admin"].Name; got != "admin" {
		t.Fatalf("runtime ACL mutation escaped: %q", got)
	}
	if !bytes.Equal(after.State.IdentityPrivateKey, originalIdentityKey) {
		t.Fatalf("common identity key changed")
	}
}

func TestComposeLinuxStateViewHandlesEmptyPartitions(t *testing.T) {
	view := composeLinuxStateView(corestate.View{}, nil)
	if view == nil || view.Network == nil || view.SyncPeers == nil {
		t.Fatalf("empty composed view = %+v", view)
	}
}
