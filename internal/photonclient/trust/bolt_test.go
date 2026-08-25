package trust

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestLoadBoltSnapshotUsesSharedGossipVerification(t *testing.T) {
	network, rootPub, _, _ := signedNetwork(t)
	path := saveNetwork(t, network)
	snapshot, err := LoadBoltSnapshot(path, "node-a.catofes.", rootPub, time.Unix(1_000, 0), generousLimits())
	if err != nil {
		t.Fatalf("LoadBoltSnapshot: %v", err)
	}
	if snapshot.Revision != 1 || snapshot.ManagedZone != "node-a.catofes." {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	record := snapshot.Network.Zones[snapshot.ManagedZone].Records["identity"]
	if record == nil || string(record.Value) != "node-a" {
		t.Fatalf("verified record = %#v", record)
	}
	if err := photoncrypto.VerifyChain(snapshot.Network, snapshot.ManagedZone, time.Unix(1_000, 0)); err != nil {
		t.Fatalf("verified chain: %v", err)
	}
}

func TestLoadBoltSnapshotRejectsWrongPinnedRoot(t *testing.T) {
	network, _, _, _ := signedNetwork(t)
	wrong, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = LoadBoltSnapshot(saveNetwork(t, network), "node-a.catofes.", wrong, time.Unix(1_000, 0), generousLimits())
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v, want pinned-root failure", err)
	}
}

func TestLoadBoltSnapshotRejectsTamperedRecord(t *testing.T) {
	network, rootPub, _, _ := signedNetwork(t)
	network.Zones["node-a.catofes."].Records["identity"].Value[0] ^= 0xff
	_, err := LoadBoltSnapshot(saveNetwork(t, network), "node-a.catofes.", rootPub, time.Unix(1_000, 0), generousLimits())
	if err == nil || !strings.Contains(err.Error(), "value hash mismatch") {
		t.Fatalf("error = %v, want record verification failure", err)
	}
}

func TestLoadBoltSnapshotRejectsRevokedManagedZone(t *testing.T) {
	network, rootPub, _, parentPriv := signedNetwork(t)
	delegation := network.Zones["catofes."].Delegations["node-a.catofes."]
	revocation := &zone.DelegationRevocation{
		ChildZone:             "node-a.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  append([]byte(nil), delegation.AuthorityHash...),
		Reason:                "compromised",
		RevokedAt:             900,
	}
	if err := photoncrypto.SignDelegationRevocation(revocation, "catofes.", parentPriv); err != nil {
		t.Fatal(err)
	}
	network.Zones["catofes."].Revocations["node-a.catofes."] = revocation
	_, err := LoadBoltSnapshot(saveNetwork(t, network), "node-a.catofes.", rootPub, time.Unix(1_000, 0), generousLimits())
	if err == nil || !strings.Contains(err.Error(), "zone revoked") {
		t.Fatalf("error = %v, want revocation failure", err)
	}
}

func TestStaticSourceReturnsDetachedSnapshots(t *testing.T) {
	network, rootPub, _, _ := signedNetwork(t)
	snapshot, err := LoadBoltSnapshot(saveNetwork(t, network), "node-a.catofes.", rootPub, time.Unix(1_000, 0), generousLimits())
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewStaticSource(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	first, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	delete(first.Network.Zones, first.ManagedZone)
	second, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.Network.Zones[second.ManagedZone] == nil {
		t.Fatal("caller mutation escaped into static source")
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := <-source.Changes(); ok {
		t.Fatal("changes channel remains open after Close")
	}
}

func signedNetwork(t *testing.T) (*zone.NetworkState, ed25519.PublicKey, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	childPub, childPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	all := []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate, zone.PermAllocateIP}}}
	rootAuthority := &zone.ZoneAuthority{Zone: zone.RootZone, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: rootPub, Capabilities: all}}}
	parentAuthority := zone.ZoneAuthority{Zone: "catofes.", Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: childPub, Capabilities: all}}}
	managedAuthority := zone.ZoneAuthority{Zone: "node-a.catofes.", Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: childPub, Capabilities: all}}}

	parentDelegation := &zone.Delegation{ZoneName: "catofes.", Authority: parentAuthority}
	if err := photoncrypto.SignDelegation(parentDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatal(err)
	}
	managedDelegation := &zone.Delegation{ZoneName: "node-a.catofes.", Authority: managedAuthority}
	if err := photoncrypto.SignDelegation(managedDelegation, "catofes.", childPriv); err != nil {
		t.Fatal(err)
	}
	record := &zone.Record{Zone: "node-a.catofes.", Key: "identity", Type: "identity", Value: []byte("node-a"), Version: 1, Timestamp: 1_000}
	if err := photoncrypto.SignRecord(record, childPriv); err != nil {
		t.Fatal(err)
	}

	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	network.Zones[zone.RootZone].Delegations["catofes."] = parentDelegation
	network.Zones["catofes."] = zone.NewZoneState("catofes.", &parentAuthority)
	network.Zones["catofes."].Delegations["node-a.catofes."] = managedDelegation
	network.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", &managedAuthority)
	network.Zones["node-a.catofes."].Records[record.Key] = record
	return network, rootPub, rootPriv, childPriv
}

func saveNetwork(t *testing.T, network *zone.NetworkState) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "photon.db")
	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveNetwork(network); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func generousLimits() gossip.SyncLimits {
	return gossip.SyncLimits{MaxZones: 16, MaxRecords: 1024, MaxBytes: 1 << 20}
}
