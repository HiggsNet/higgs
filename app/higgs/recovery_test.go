package main

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestRecoveryChainZonesRootToLeaf(t *testing.T) {
	got := recoveryChainZones("node-b.pek.catofes.")
	want := []zone.ZonePath{zone.RootZone, "catofes.", "pek.catofes.", "node-b.pek.catofes."}
	if len(got) != len(want) {
		t.Fatalf("chain len = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("chain[%d] = %s, want %s; chain=%#v", i, got[i], want[i], got)
		}
	}
}

func TestRecoveryApplySnapshotRestoresManagedZoneDelegations(t *testing.T) {
	source, _ := buildTestNetworkState(t)
	snapshot, err := gossip.Snapshot(source.Network, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(catofes): %v", err)
	}

	target := cloneStateFile(source)
	target.ManagedZone = "catofes."
	delete(target.Network.Zones["catofes."].Delegations, "node-b.catofes.")
	rootKey := target.Network.Zones[zone.RootZone].Authority.Keys[0].Key
	rt := &Runtime{
		Config: &appConfig{TrustedRootPublicKey: rootKey},
		Clock:  func() time.Time { return time.Unix(123, 0) },
	}

	result, err := applyRecoveryZoneSnapshot(rt, target, snapshot)
	if err != nil {
		t.Fatalf("applyRecoveryZoneSnapshot: %v", err)
	}
	if result.Zone != "catofes." {
		t.Fatalf("result zone = %s, want catofes.", result.Zone)
	}
	if target.Network.Zones["catofes."].Delegations["node-b.catofes."] == nil {
		t.Fatalf("node-b delegation was not restored")
	}
}

func TestRecoveryApplySnapshotsCanRestoreChainInOrder(t *testing.T) {
	source, _ := buildTestNetworkState(t)
	rootSnapshot, err := gossip.Snapshot(source.Network, zone.RootZone)
	if err != nil {
		t.Fatalf("Snapshot(root): %v", err)
	}
	catofesSnapshot, err := gossip.Snapshot(source.Network, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(catofes): %v", err)
	}
	nodeSnapshot, err := gossip.Snapshot(source.Network, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot(node-b): %v", err)
	}

	rootKey := source.Network.Zones[zone.RootZone].Authority.Keys[0].Key
	target := cloneStateFile(source)
	target.ManagedZone = "node-b.catofes."
	target.Network = zone.NewNetworkState()
	target.Network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootKey,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	})
	configureValidation(target.Network)
	rt := &Runtime{
		Config: &appConfig{TrustedRootPublicKey: rootKey},
		Clock:  func() time.Time { return time.Unix(123, 0) },
	}

	for _, snapshot := range []*gossip.ZoneSnapshot{rootSnapshot, catofesSnapshot, nodeSnapshot} {
		if _, err := applyRecoveryZoneSnapshot(rt, target, snapshot); err != nil {
			t.Fatalf("applyRecoveryZoneSnapshot(%s): %v", snapshot.Zone, err)
		}
	}
	if target.Network.Zones[zone.RootZone].Delegations["catofes."] == nil {
		t.Fatalf("catofes delegation was not restored")
	}
	if target.Network.Zones["catofes."].Delegations["node-b.catofes."] == nil {
		t.Fatalf("node-b delegation was not restored")
	}
	if _, err := applyRecoveryZoneSnapshot(rt, target, nodeSnapshot); err != nil {
		t.Fatalf("reapplying leaf snapshot should be idempotent: %v", err)
	}
}

func TestRecoveryRootSnapshotMustMatchTrustedRoot(t *testing.T) {
	source, _ := buildTestNetworkState(t)
	snapshot, err := gossip.Snapshot(source.Network, zone.RootZone)
	if err != nil {
		t.Fatalf("Snapshot(root): %v", err)
	}
	target := cloneStateFile(source)
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(other): %v", err)
	}
	rt := &Runtime{
		Config: &appConfig{TrustedRootPublicKey: otherPub},
		Clock:  func() time.Time { return time.Unix(123, 0) },
	}

	_, err = applyRecoveryZoneSnapshot(rt, target, snapshot)
	if err == nil || !strings.Contains(err.Error(), "trusted_root_public_key") {
		t.Fatalf("applyRecoveryZoneSnapshot error = %v, want trusted root mismatch", err)
	}
}
