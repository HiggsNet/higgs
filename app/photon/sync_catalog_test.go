package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func executeTestGossipSnapshots(service *DaemonService, controller *daemonGossipIO, peerID string, actions []gossip.ApplySnapshotAction) corehost.GossipExecutionResult {
	syncActions := make([]gossip.SyncAction, len(actions))
	for index := range actions {
		syncActions[index] = actions[index]
	}
	return service.hostRuntime.ExecuteGossipActions(context.Background(), &gossip.SyncSession{PeerID: peerID}, syncActions, controller)
}

func TestApplySyncSnapshotRecordsRejectedDigest(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2000, 0)
	badRecord := &zone.Record{Zone: "node-b.catofes.", Key: "bad", Type: "policy.string", Value: []byte("original"), Version: 1, Timestamp: now.Unix()}
	if err := photoncrypto.SignRecord(badRecord, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	badRecord.Value = []byte("tampered")
	snapshot := &corestate.ZoneSnapshot{Zone: "node-b.catofes.", Authority: state.Network.Zones["node-b.catofes."].Authority, Records: map[string]*zone.Record{"bad": badRecord}}
	rt := &Runtime{StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	controller := &daemonGossipIO{daemon: service}
	if result := executeTestGossipSnapshots(service, controller, "node-b.catofes.", []gossip.ApplySnapshotAction{{PeerID: "node-b.catofes.", Snapshot: snapshot}}); result.Aborted {
		t.Fatal("snapshot execution aborted")
	}
	rejected := service.StateStore.common.ReadView().Gossip.Peers["node-b.catofes."].RejectedObjects[snapshot.Zone]
	if !bytes.Equal(rejected.RootHash, corestate.ZoneRoot(corestate.ZoneStateFromSnapshot(snapshot))) || rejected.UntilUnix <= now.Unix() {
		t.Fatal("invalid snapshot did not record a rejected digest")
	}
}

func TestParentSnapshotRefreshesManagedZoneAuthority(t *testing.T) {
	state, config, rootPriv := buildManagedAuthorityRefreshState(t)
	now := time.Unix(2000, 0)
	managed := state.ManagedZone
	local := state.Network.Zones[managed]
	localRecord := &zone.Record{
		Zone:      managed,
		Key:       "local-note",
		Type:      "policy.string",
		Value:     []byte("keep me"),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := photoncrypto.SignRecord(localRecord, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord(local-note): %v", err)
	}
	if err := state.Network.PutAt(localRecord, now); err != nil {
		t.Fatalf("PutAt(local-note): %v", err)
	}
	local.Delegations["leaf.catofes."] = &zone.Delegation{ZoneName: "leaf.catofes."}

	snapshot := managedAuthorityGrantSnapshot(t, state.Network, managed, rootPriv, zone.PermAllocateIP)
	rt := &Runtime{StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	controller := &daemonGossipIO{daemon: service}
	if result := executeTestGossipSnapshots(service, controller, "root-admin", []gossip.ApplySnapshotAction{{PeerID: "root-admin", Snapshot: snapshot}}); result.Aborted || !result.NetworkChanged {
		t.Fatal("root grant snapshot was not committed")
	}

	committed, _ := service.StateStore.Snapshot()
	managedState := committed.Network.Zones[managed]
	if managedState.Authority.Epoch != 2 {
		t.Fatalf("managed authority epoch = %d, want 2", managedState.Authority.Epoch)
	}
	if !authorityHasPermission(managedState.Authority, zone.PermAllocateIP) {
		t.Fatal("managed authority missing allocate-ip")
	}
	if got := managedState.Records["local-note"]; got == nil || string(got.Value) != "keep me" {
		t.Fatalf("local record = %+v, want preserved", got)
	}
	if managedState.Delegations["leaf.catofes."] == nil {
		t.Fatal("local child delegation was not preserved")
	}
	if len(managedState.ParentProof) != 1 || managedState.ParentProof[0].AuthorityEpoch != 2 || !authorityHasPermission(&managedState.ParentProof[0].Authority, zone.PermAllocateIP) {
		t.Fatalf("managed parent proof = %+v, want refreshed epoch 2 proof", managedState.ParentProof)
	}
	if err := photoncrypto.VerifyChain(committed.Network, managed, now); err != nil {
		t.Fatalf("VerifyChain(managed): %v", err)
	}
}

func TestParentSnapshotRejectsManagedAuthorityRefreshForDifferentKey(t *testing.T) {
	state, config, rootPriv := buildManagedAuthorityRefreshState(t)
	now := time.Unix(2000, 0)
	managed := state.ManagedZone
	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(other): %v", err)
	}
	remote := zone.CloneNetworkState(state.Network)
	authority := cloneAuthorityForJoinBundle(remote.Zones[managed].Authority)
	authority.Epoch++
	authority.Keys[0].Key = append(ed25519.PublicKey(nil), otherPriv.Public().(ed25519.PublicKey)...)
	delegation := &zone.Delegation{ZoneName: managed, Scope: zone.DelegationScopeDirectChild, Authority: *authority}
	if err := photoncrypto.SignDelegation(delegation, managed.Parent(), rootPriv); err != nil {
		t.Fatalf("SignDelegation(refresh): %v", err)
	}
	remote.Zones[managed.Parent()].Delegations[managed] = delegation
	snapshot, err := corestate.Snapshot(remote, managed.Parent())
	if err != nil {
		t.Fatalf("Snapshot(parent): %v", err)
	}

	rt := &Runtime{StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	controller := &daemonGossipIO{daemon: service}
	if result := executeTestGossipSnapshots(service, controller, "root-admin", []gossip.ApplySnapshotAction{{PeerID: "root-admin", Snapshot: snapshot}}); result.Aborted {
		t.Fatal("snapshot execution aborted")
	}

	committed, _ := service.StateStore.Snapshot()
	if got := committed.Network.Zones[managed].Authority.Epoch; got != 1 {
		t.Fatalf("managed authority epoch = %d, want rollback to 1", got)
	}
	if got := committed.Network.Zones[managed.Parent()].Delegations[managed].AuthorityEpoch; got != 1 {
		t.Fatalf("parent delegation epoch = %d, want rollback to 1", got)
	}
	if err := photoncrypto.VerifyChain(committed.Network, managed, now); err != nil {
		t.Fatalf("VerifyChain(managed after rollback): %v", err)
	}
}

func TestPrepareStartupStateRefreshesCachedManagedAuthority(t *testing.T) {
	state, config, rootPriv := buildManagedAuthorityRefreshState(t)
	now := time.Unix(2000, 0)
	managed := state.ManagedZone
	snapshot := managedAuthorityGrantSnapshot(t, state.Network, managed, rootPriv, zone.PermAllocateIP)
	state.Network.Zones[managed.Parent()].Delegations[managed] = cloneDelegationForJoinBundle(snapshot.Delegations[managed])
	config.DisableEndpointPublish = true

	rt := &Runtime{StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState(inconsistent): %v", err)
	}
	service := newTestDaemonService(rt, state, config, defaultDaemonInterval)
	if changed, err := service.prepareStartupState(); err != nil {
		t.Fatalf("prepareStartupState: %v", err)
	} else if !changed {
		t.Fatal("prepareStartupState did not refresh cached managed authority")
	}

	committed, _ := service.StateStore.Snapshot()
	if got := committed.Network.Zones[managed].Authority.Epoch; got != 2 {
		t.Fatalf("managed authority epoch = %d, want 2", got)
	}
	if !authorityHasPermission(committed.Network.Zones[managed].Authority, zone.PermAllocateIP) {
		t.Fatal("managed authority missing allocate-ip after startup refresh")
	}
	if err := photoncrypto.VerifyChain(committed.Network, managed, now); err != nil {
		t.Fatalf("VerifyChain(managed): %v", err)
	}
	reloaded := service.currentState()
	if got := reloaded.Network.Zones[managed].Authority.Epoch; got != 2 {
		t.Fatalf("persisted managed authority epoch = %d, want 2", got)
	}
}

func buildManagedAuthorityRefreshState(t *testing.T) (*stateFile, *syncConfigFile, ed25519.PrivateKey) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	managedPub, managedPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(managed): %v", err)
	}
	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	}
	managedAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: managedPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	}
	delegation := &zone.Delegation{ZoneName: "catofes.", Scope: zone.DelegationScopeDirectChild, Authority: *managedAuthority}
	if err := photoncrypto.SignDelegation(delegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(managed): %v", err)
	}
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	network.Zones[zone.RootZone].Delegations["catofes."] = delegation
	network.Zones["catofes."] = zone.NewZoneState("catofes.", managedAuthority)
	network.Zones["catofes."].ParentProof = []*zone.Delegation{cloneDelegationForJoinBundle(delegation)}
	configureValidation(network)
	state := &stateFile{ManagedZone: "catofes.", ZonePrivateKey: managedPriv, Network: network}
	config := &syncConfigFile{PeerID: "catofes.", ListenAddr: "127.0.0.1:0"}
	return state, config, rootPriv
}

func managedAuthorityGrantSnapshot(t *testing.T, network *zone.NetworkState, managed zone.ZonePath, parentPriv ed25519.PrivateKey, permissions ...zone.Permission) *corestate.ZoneSnapshot {
	t.Helper()
	remote := zone.CloneNetworkState(network)
	authority := cloneAuthorityForJoinBundle(remote.Zones[managed].Authority)
	grantPermissionsToAuthority(authority, permissions)
	authority.Epoch++
	delegation := &zone.Delegation{ZoneName: managed, Scope: zone.DelegationScopeDirectChild, Authority: *authority}
	if err := photoncrypto.SignDelegation(delegation, managed.Parent(), parentPriv); err != nil {
		t.Fatalf("SignDelegation(grant): %v", err)
	}
	remote.Zones[managed.Parent()].Delegations[managed] = delegation
	remote.Zones[managed].Authority = authority
	snapshot, err := corestate.Snapshot(remote, managed.Parent())
	if err != nil {
		t.Fatalf("Snapshot(parent): %v", err)
	}
	return snapshot
}
