package main

import (
	"path/filepath"
	"testing"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestRootInitHasAllAuthorityPermissions(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "root.yaml")
	writeConfig(t, configPath, filepath.Join(dir, "root"))
	t.Setenv("HIGGS_CONFIG", configPath)

	if err := initRootState(); err != nil {
		t.Fatalf("initRootState: %v", err)
	}
	state, err := loadState()
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	root := state.Network.Zones[zone.RootZone]
	for _, permission := range allAuthorityPermissions() {
		if !authorityHasPermission(root.Authority, permission) {
			t.Fatalf("root authority missing permission %s", permission)
		}
	}
}

func TestAuthorityGrantReissuesChildDelegation(t *testing.T) {
	dir := t.TempDir()
	adminConfig := filepath.Join(dir, "admin.yaml")
	catofesConfig := filepath.Join(dir, "catofes.yaml")
	catofesKeyPath := filepath.Join(dir, "catofes.key.json")
	catofesRequestPath := filepath.Join(dir, "catofes.request.b64")
	catofesBundlePath := filepath.Join(dir, "catofes.bundle.b64")
	grantBundlePath := filepath.Join(dir, "catofes.grant.b64")

	writeConfig(t, adminConfig, filepath.Join(dir, "admin"))
	t.Setenv("HIGGS_CONFIG", adminConfig)
	if err := initRootState(); err != nil {
		t.Fatalf("initRootState(admin): %v", err)
	}

	writeConfig(t, catofesConfig, filepath.Join(dir, "catofes"))
	t.Setenv("HIGGS_CONFIG", catofesConfig)
	if err := keygen(catofesKeyPath); err != nil {
		t.Fatalf("keygen(catofes): %v", err)
	}
	if err := createJoinRequest("catofes.", catofesKeyPath, catofesRequestPath); err != nil {
		t.Fatalf("createJoinRequest(catofes): %v", err)
	}
	t.Setenv("HIGGS_CONFIG", adminConfig)
	if err := issueDelegation(catofesRequestPath, catofesBundlePath, nil); err != nil {
		t.Fatalf("issueDelegation(catofes): %v", err)
	}
	t.Setenv("HIGGS_CONFIG", catofesConfig)
	if err := acceptJoinBundle(catofesBundlePath, catofesKeyPath); err != nil {
		t.Fatalf("acceptJoinBundle(initial): %v", err)
	}
	if err := putRecord("catofes.", "local-note", []byte("keep me"), "policy.string"); err != nil {
		t.Fatalf("putRecord(catofes local): %v", err)
	}

	t.Setenv("HIGGS_CONFIG", adminConfig)
	state, err := loadState()
	if err != nil {
		t.Fatalf("loadState admin before grant: %v", err)
	}
	before := state.Network.Zones["catofes."].Authority.Epoch
	if authorityHasPermission(state.Network.Zones["catofes."].Authority, zone.PermAllocateIP) {
		t.Fatalf("catofes authority unexpectedly has allocate-ip before grant")
	}

	if err := grantAuthority("catofes.", []zone.Permission{zone.PermAllocateIP}, grantBundlePath); err != nil {
		t.Fatalf("grantAuthority(catofes): %v", err)
	}
	state, err = loadState()
	if err != nil {
		t.Fatalf("loadState admin after grant: %v", err)
	}
	catofes := state.Network.Zones["catofes."]
	if catofes.Authority.Epoch != before+1 {
		t.Fatalf("catofes epoch = %d, want %d", catofes.Authority.Epoch, before+1)
	}
	if !authorityHasPermission(catofes.Authority, zone.PermAllocateIP) {
		t.Fatalf("catofes authority missing allocate-ip after grant")
	}
	delegation := state.Network.Zones[zone.RootZone].Delegations["catofes."]
	if delegation == nil || !authorityHasPermission(&delegation.Authority, zone.PermAllocateIP) {
		t.Fatalf("root delegation missing updated catofes authority")
	}

	t.Setenv("HIGGS_CONFIG", catofesConfig)
	if err := acceptJoinBundle(grantBundlePath, ""); err != nil {
		t.Fatalf("acceptJoinBundle(grant): %v", err)
	}
	childState, err := loadState()
	if err != nil {
		t.Fatalf("loadState catofes after grant accept: %v", err)
	}
	if !authorityHasPermission(childState.Network.Zones["catofes."].Authority, zone.PermAllocateIP) {
		t.Fatalf("catofes local authority missing allocate-ip after accepting grant bundle")
	}
	if childState.Network.Zones["catofes."].Records["local-note"] == nil {
		t.Fatalf("catofes local record was lost while accepting grant bundle")
	}
}

func authorityHasPermission(authority *zone.ZoneAuthority, permission zone.Permission) bool {
	if authority == nil {
		return false
	}
	for _, key := range authority.Keys {
		for _, capability := range key.Capabilities {
			for _, existing := range capability.Permissions {
				if existing == permission {
					return true
				}
			}
		}
	}
	return false
}
