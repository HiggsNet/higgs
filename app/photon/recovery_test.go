package main

import (
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
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
	snapshot, err := corestate.Snapshot(source.Network, "catofes.")
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

func TestRecoveryImportNoopDoesNotCommitOrNotify(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	now := time.Unix(1000, 0)
	snapshot, err := corestate.Snapshot(state.Network, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot(node-b): %v", err)
	}

	service := newTestDaemonService(&Runtime{Config: defaultAppConfig(), Clock: func() time.Time { return now }}, state, config, defaultDaemonInterval)
	if _, _, err := service.handleRecoveryImportZoneEvent(snapshot); err != nil {
		t.Fatalf("handleRecoveryImportZoneEvent(first): %v", err)
	}
	notifications := 0
	service.Hooks.OnStateChanged = func(*stateFile) { notifications++ }
	beforeRevision := service.StateStore.Meta().Revision
	result, _, err := service.handleRecoveryImportZoneEvent(snapshot)
	if err != nil {
		t.Fatalf("handleRecoveryImportZoneEvent(no-op): %v", err)
	}
	if result.NetworkChanged {
		t.Fatalf("identical recovery snapshot result = %+v, want no network change", result)
	}
	if revision := service.StateStore.Meta().Revision; revision != beforeRevision {
		t.Fatalf("no-op recovery revision = %d, want unchanged %d", revision, beforeRevision)
	}
	if notifications != 0 {
		t.Fatalf("no-op recovery emitted %d state-change notifications", notifications)
	}
}

func TestRecoveryExportImportOfflineRootIPAMRecords(t *testing.T) {
	dir := t.TempDir()
	adminConfig := filepath.Join(dir, "admin.yaml")
	catofesConfig := filepath.Join(dir, "catofes.yaml")
	catofesKeyPath := filepath.Join(dir, "catofes.key.json")
	catofesRequestPath := filepath.Join(dir, "catofes.request.b64")
	catofesBundlePath := filepath.Join(dir, "catofes.bundle.b64")
	rootSnapshotPath := filepath.Join(dir, "root.snapshot.b64")

	writeConfig(t, adminConfig, filepath.Join(dir, "admin"))
	t.Setenv("PHOTON_CONFIG", adminConfig)
	if err := initRootState(); err != nil {
		t.Fatalf("initRootState(admin): %v", err)
	}

	writeConfig(t, catofesConfig, filepath.Join(dir, "catofes"))
	t.Setenv("PHOTON_CONFIG", catofesConfig)
	if err := keygen(catofesKeyPath); err != nil {
		t.Fatalf("keygen(catofes): %v", err)
	}
	if err := createJoinRequest("catofes.", catofesKeyPath, catofesRequestPath); err != nil {
		t.Fatalf("createJoinRequest(catofes): %v", err)
	}
	t.Setenv("PHOTON_CONFIG", adminConfig)
	if err := issueDelegation(catofesRequestPath, catofesBundlePath, nil, true); err != nil {
		t.Fatalf("issueDelegation(catofes): %v", err)
	}
	if err := createIPAMPool(".", "2a0d:2905::/32", ".", true); err != nil {
		t.Fatalf("createIPAMPool(root): %v", err)
	}
	if err := recoveryExportZone(zone.RootZone, rootSnapshotPath); err != nil {
		t.Fatalf("recoveryExportZone(root): %v", err)
	}

	t.Setenv("PHOTON_CONFIG", catofesConfig)
	if err := acceptJoinBundle(catofesBundlePath, catofesKeyPath, true); err != nil {
		t.Fatalf("acceptJoinBundle(catofes): %v", err)
	}
	if err := recoveryImportZone(rootSnapshotPath, true); err != nil {
		t.Fatalf("recoveryImportZone(root): %v", err)
	}
	state, err := loadState()
	if err != nil {
		t.Fatalf("loadState(catofes): %v", err)
	}
	key, err := routing.NormalizeIPAMPoolKey("2a0d:2905::/32")
	if err != nil {
		t.Fatalf("NormalizeIPAMPoolKey: %v", err)
	}
	if state.Network.Zones[zone.RootZone].Records[key] == nil {
		t.Fatalf("imported root snapshot missing IPAM pool record %s", key)
	}
}

func TestRecoveryImportZoneEventAppliesToDaemonState(t *testing.T) {
	dir := t.TempDir()
	adminConfig := filepath.Join(dir, "admin.yaml")
	catofesConfig := filepath.Join(dir, "catofes.yaml")
	catofesKeyPath := filepath.Join(dir, "catofes.key.json")
	catofesRequestPath := filepath.Join(dir, "catofes.request.b64")
	catofesBundlePath := filepath.Join(dir, "catofes.bundle.b64")

	writeConfig(t, adminConfig, filepath.Join(dir, "admin"))
	t.Setenv("PHOTON_CONFIG", adminConfig)
	if err := initRootState(); err != nil {
		t.Fatalf("initRootState(admin): %v", err)
	}

	writeConfig(t, catofesConfig, filepath.Join(dir, "catofes"))
	t.Setenv("PHOTON_CONFIG", catofesConfig)
	if err := keygen(catofesKeyPath); err != nil {
		t.Fatalf("keygen(catofes): %v", err)
	}
	if err := createJoinRequest("catofes.", catofesKeyPath, catofesRequestPath); err != nil {
		t.Fatalf("createJoinRequest(catofes): %v", err)
	}
	t.Setenv("PHOTON_CONFIG", adminConfig)
	if err := issueDelegation(catofesRequestPath, catofesBundlePath, nil, true); err != nil {
		t.Fatalf("issueDelegation(catofes): %v", err)
	}
	if err := createIPAMPool(".", "2a0d:2905::/32", ".", true); err != nil {
		t.Fatalf("createIPAMPool(root): %v", err)
	}
	adminState, err := loadState()
	if err != nil {
		t.Fatalf("loadState(admin): %v", err)
	}
	snapshot, err := corestate.Snapshot(adminState.Network, zone.RootZone)
	if err != nil {
		t.Fatalf("Snapshot(root): %v", err)
	}

	t.Setenv("PHOTON_CONFIG", catofesConfig)
	if err := acceptJoinBundle(catofesBundlePath, catofesKeyPath, true); err != nil {
		t.Fatalf("acceptJoinBundle(catofes): %v", err)
	}
	rt, err := NewRuntime()
	if err != nil {
		t.Fatalf("NewRuntime(catofes): %v", err)
	}
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(catofes): %v", err)
	}
	config, err := rt.SyncConfig(state)
	if err != nil {
		t.Fatalf("SyncConfig(catofes): %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)

	result, _, _ := service.handleEvent(daemonEvent{
		Type:     daemonEventRecoveryImportZone,
		Snapshot: snapshot,
	})
	if result.Error != nil {
		t.Fatalf("handle recovery import event: %v", result.Error)
	}

	reloaded := service.currentState()
	key, err := routing.NormalizeIPAMPoolKey("2a0d:2905::/32")
	if err != nil {
		t.Fatalf("NormalizeIPAMPoolKey: %v", err)
	}
	if reloaded.Network.Zones[zone.RootZone].Records[key] == nil {
		t.Fatalf("daemon import missing IPAM pool record %s", key)
	}
}

func TestRecoveryApplySnapshotsCanRestoreChainInOrder(t *testing.T) {
	source, _ := buildTestNetworkState(t)
	rootSnapshot, err := corestate.Snapshot(source.Network, zone.RootZone)
	if err != nil {
		t.Fatalf("Snapshot(root): %v", err)
	}
	catofesSnapshot, err := corestate.Snapshot(source.Network, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(catofes): %v", err)
	}
	nodeSnapshot, err := corestate.Snapshot(source.Network, "node-b.catofes.")
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

	for _, snapshot := range []*corestate.ZoneSnapshot{rootSnapshot, catofesSnapshot, nodeSnapshot} {
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
	snapshot, err := corestate.Snapshot(source.Network, zone.RootZone)
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
