package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestParseConfigYAMLIdentity(t *testing.T) {
	config := defaultAppConfig()
	input := `
gossip:
  init:
    managed_zone: node-b.catofes.
    key_path: keys/node-b.json
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if config.ManagedZone != "node-b.catofes." || config.Identity.KeyPath != "keys/node-b.json" {
		t.Fatalf("identity config = zone:%s key:%q", config.ManagedZone, config.Identity.KeyPath)
	}
}

func TestLoadStateAutoJoinCreatesPendingBootstrapState(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := writeTestPrivateKey(t, dir, "node-b")
	rootPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	config := defaultAppConfig()
	config.StatePath = filepath.Join(dir, "photon.db")
	config.ManagedZone = "node-b.catofes."
	config.Identity.KeyPath = keyPath
	config.TrustedRootPublicKey = rootPub
	config.Bootstrap = []syncConfigPeer{{ID: "catofes.", Addr: "127.0.0.1:33434"}}
	rt := &Runtime{Config: config, StatePath: config.StatePath, Clock: func() time.Time { return time.Unix(1000, 0) }}

	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if state.ManagedZone != "node-b.catofes." || !autoJoinPending(state) {
		t.Fatalf("state = zone:%s pending:%v", state.ManagedZone, autoJoinPending(state))
	}
	if !equalPublicKey(state.ZonePrivateKey.Public().(ed25519.PublicKey), pub) {
		t.Fatalf("ZonePrivateKey public mismatch")
	}
	root := state.Network.Zones[zone.RootZone]
	if root == nil || root.Authority == nil || !authorityHasKey(root.Authority, rootPub) {
		t.Fatalf("trusted root authority missing: %+v", root)
	}

	reloaded, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(reloaded): %v", err)
	}
	if reloaded.IdentityKeyPath == "" || reloaded.IdentityKeyPath != state.IdentityKeyPath {
		t.Fatalf("IdentityKeyPath = %q, want %q", reloaded.IdentityKeyPath, state.IdentityKeyPath)
	}
}

func TestTryAdoptAutoJoinDelegationCreatesManagedZone(t *testing.T) {
	dir := t.TempDir()
	state, keyPath := buildPendingAutoJoinState(t, dir, "node-b.catofes.", true)
	key, err := readPrivateKeyFile(keyPath)
	if err != nil {
		t.Fatalf("readPrivateKeyFile: %v", err)
	}
	if !autoJoinPending(state) {
		t.Fatalf("state should start pending")
	}

	adopted, err := tryAdoptAutoJoinDelegation(state, time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("tryAdoptAutoJoinDelegation: %v", err)
	}
	if !adopted {
		t.Fatalf("adopted = false, want true")
	}
	if autoJoinPending(state) {
		t.Fatalf("state still pending after adoption")
	}
	zs := state.Network.Zones[state.ManagedZone]
	if zs == nil || zs.Authority == nil {
		t.Fatalf("managed zone was not created")
	}
	if !authorityHasKey(zs.Authority, key.PublicKey) {
		t.Fatalf("managed zone authority missing local key")
	}
	if len(zs.ParentProof) != 1 || zs.ParentProof[0].ZoneName != state.ManagedZone {
		t.Fatalf("parent proof = %#v, want direct proof for managed zone", zs.ParentProof)
	}
	if err := photoncrypto.VerifyChain(state.Network, state.ManagedZone, time.Unix(1000, 0)); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestTryAdoptAutoJoinDelegationIgnoresKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", false)

	adopted, err := tryAdoptAutoJoinDelegation(state, time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("tryAdoptAutoJoinDelegation: %v", err)
	}
	if adopted {
		t.Fatalf("adopted = true, want false")
	}
	if state.Network.Zones[state.ManagedZone] != nil {
		t.Fatalf("managed zone should not be created for mismatched delegation")
	}
	if !autoJoinPending(state) {
		t.Fatalf("state should remain pending")
	}
}

func TestLoadStateRejectsConfiguredIdentityMismatch(t *testing.T) {
	dir := t.TempDir()
	state, keyPath := buildIdentityState(t, dir, "node-b.catofes.")
	config := defaultAppConfig()
	config.StatePath = filepath.Join(dir, "photon.db")
	config.ManagedZone = "node-b.catofes."
	config.Identity.KeyPath = keyPath
	rt := &Runtime{Config: config, StatePath: config.StatePath}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	otherKeyPath, _ := writeTestPrivateKey(t, dir, "other")
	config.Identity.KeyPath = otherKeyPath
	if _, err := rt.LoadState(); err == nil || !strings.Contains(err.Error(), "public key does not match DB ZonePrivateKey") {
		t.Fatalf("LoadState mismatch error = %v", err)
	}
}

func TestLoadStateRejectsConfiguredManagedZoneMismatch(t *testing.T) {
	dir := t.TempDir()
	state, keyPath := buildIdentityState(t, dir, "node-b.catofes.")
	config := defaultAppConfig()
	config.StatePath = filepath.Join(dir, "photon.db")
	config.ManagedZone = "node-a.catofes."
	config.Identity.KeyPath = keyPath
	rt := &Runtime{Config: config, StatePath: config.StatePath}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	if _, err := rt.LoadState(); err == nil || !strings.Contains(err.Error(), "does not match DB ManagedZone") {
		t.Fatalf("LoadState managed_zone mismatch error = %v", err)
	}
}

func TestDaemonReloadRejectsIdentityKeyPathChange(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	state, keyPath := buildIdentityState(t, dir, "node-b.catofes.")
	otherKeyPath := copyTestPrivateKey(t, keyPath, filepath.Join(dir, "copy.key.json"))
	dataDir := filepath.Join(dir, "data")
	statePath := filepath.Join(dataDir, "photon.db")
	t.Setenv("PHOTON_CONFIG", configPath)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeIdentityConfig(t, configPath, dataDir, "node-b.catofes.", keyPath)

	appConfig := defaultAppConfig()
	appConfig.DataDir = dataDir
	appConfig.StatePath = statePath
	appConfig.ManagedZone = "node-b.catofes."
	appConfig.Identity.KeyPath = keyPath
	state.IdentityKeyPath, _ = canonicalIdentityKeyPath(keyPath)
	rt := &Runtime{Config: appConfig, StatePath: statePath}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	config := syncConfigFromAppConfig(appConfig, state)
	service := newDaemonService(rt, state, config, time.Second)

	writeIdentityConfig(t, configPath, dataDir, "node-b.catofes.", otherKeyPath)
	result, syncNow, shutdown := service.handleEvent(daemonEvent{Type: daemonEventReloadConfig})
	if result.Error == nil || !strings.Contains(result.Error.Error(), "identity.key_path") {
		t.Fatalf("reload error = %v, want identity.key_path rejection", result.Error)
	}
	if syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want false/false", syncNow, shutdown)
	}

	writeIdentityConfig(t, configPath, dataDir, "node-b.catofes.", keyPath)
	result, syncNow, shutdown = service.handleEvent(daemonEvent{Type: daemonEventReloadConfig})
	if result.Error != nil {
		t.Fatalf("reload matching identity: %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("matching reload syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
}

func buildPendingAutoJoinState(t *testing.T, dir string, managed zone.ZonePath, matchingDelegation bool) (*stateFile, string) {
	t.Helper()
	keyPath, pub := writeTestPrivateKey(t, dir, "identity")
	if !matchingDelegation {
		_, pub = writeTestPrivateKey(t, dir, "other")
	}
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	parentPub, parentPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(parent): %v", err)
	}
	parent := managed.Parent()
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
	parentAuthority := &zone.ZoneAuthority{
		Zone:      parent,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: parentPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	}
	childAuthority := &zone.ZoneAuthority{
		Zone:      managed,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate},
			}},
		}},
	}
	parentDelegation := &zone.Delegation{
		ZoneName:  parent,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *parentAuthority,
	}
	if err := photoncrypto.SignDelegation(parentDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(parent): %v", err)
	}
	childDelegation := &zone.Delegation{
		ZoneName:  managed,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *childAuthority,
	}
	if err := photoncrypto.SignDelegation(childDelegation, parent, parentPriv); err != nil {
		t.Fatalf("SignDelegation(child): %v", err)
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones[zone.RootZone].Delegations[parent] = parentDelegation
	ns.Zones[parent] = zone.NewZoneState(parent, parentAuthority)
	ns.Zones[parent].ParentProof = []*zone.Delegation{cloneDelegationForJoinBundle(parentDelegation)}
	ns.Zones[parent].Delegations[managed] = childDelegation
	configureValidation(ns)
	key, err := readPrivateKeyFile(keyPath)
	if err != nil {
		t.Fatalf("readPrivateKeyFile: %v", err)
	}
	return &stateFile{
		ManagedZone:    managed,
		ZonePrivateKey: key.PrivateKey,
		Network:        ns,
	}, keyPath
}

func buildIdentityState(t *testing.T, dir string, managed zone.ZonePath) (*stateFile, string) {
	t.Helper()
	keyPath, pub := writeTestPrivateKey(t, dir, "identity")
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	parent := managed.Parent()
	parentAuthority := &zone.ZoneAuthority{
		Zone:      parent,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	childAuthority := &zone.ZoneAuthority{
		Zone:      managed,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	delegation := &zone.Delegation{
		ZoneName:  managed,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *childAuthority,
	}
	if err := photoncrypto.SignDelegation(delegation, parent, rootPriv); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	ns := zone.NewNetworkState()
	ns.Zones[parent] = zone.NewZoneState(parent, parentAuthority)
	ns.Zones[managed] = zone.NewZoneState(managed, childAuthority)
	ns.Zones[parent].Delegations[managed] = delegation
	configureValidation(ns)
	key, err := readPrivateKeyFile(keyPath)
	if err != nil {
		t.Fatalf("readPrivateKeyFile: %v", err)
	}
	return &stateFile{
		ManagedZone:    managed,
		ZonePrivateKey: key.PrivateKey,
		Network:        ns,
	}, keyPath
}

func writeTestPrivateKey(t *testing.T, dir, name string) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", name, err)
	}
	path := filepath.Join(dir, name+".key.json")
	key := privateKeyFile{Type: "photon.ed25519.private.v1", PublicKey: pub, PrivateKey: priv}
	if err := writeJSONFile(path, 0o600, &key); err != nil {
		t.Fatalf("writeJSONFile(%s): %v", name, err)
	}
	return path, pub
}

func copyTestPrivateKey(t *testing.T, source, dest string) string {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("ReadFile(source): %v", err)
	}
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		t.Fatalf("WriteFile(dest): %v", err)
	}
	return dest
}

func writeIdentityConfig(t *testing.T, path, dataDir string, managed zone.ZonePath, keyPath string) {
	t.Helper()
	data := strings.Join([]string{
		"data_dir: " + dataDir,
		"gossip:",
		"  init:",
		"    managed_zone: " + string(managed),
		"    key_path: " + keyPath,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
}
