package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/Catofes/photon/pkg/core/zone"
	photoncrypto "github.com/Catofes/photon/pkg/crypto"
)

func allAuthorityPermissions() []zone.Permission {
	return []zone.Permission{
		zone.PermWrite,
		zone.PermDelegate,
		zone.PermAllocateIP,
	}
}

func defaultRootCapabilities() []zone.Capability {
	return []zone.Capability{{Permissions: allAuthorityPermissions()}}
}

func defaultDelegationCapabilities() []zone.Capability {
	return []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate}}}
}

func parseAuthorityPermissions(input []string) ([]zone.Permission, error) {
	var out []zone.Permission
	seen := map[zone.Permission]bool{}
	for _, raw := range input {
		for part := range strings.SplitSeq(raw, ",") {
			perm, err := parseAuthorityPermission(strings.TrimSpace(part))
			if err != nil {
				return nil, err
			}
			if seen[perm] {
				continue
			}
			seen[perm] = true
			out = append(out, perm)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one permission is required")
	}
	slices.Sort(out)
	return out, nil
}

func parseAuthorityPermission(raw string) (zone.Permission, error) {
	switch zone.Permission(raw) {
	case zone.PermWrite, zone.PermDelegate, zone.PermAllocateIP:
		return zone.Permission(raw), nil
	default:
		return "", fmt.Errorf("unsupported authority permission %q", raw)
	}
}

func grantDelegationPermissions(path zone.ZonePath, permissions []zone.Permission, outPath string, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	bundle, controlled, err := grantDelegationPermissionsViaControl(rt, path, permissions)
	if err != nil {
		return err
	}
	if controlled {
		if err := writeDelegationGrantBundle(bundle, outPath); err != nil {
			return err
		}
		fmt.Printf("granted delegated permissions for %s via daemon\n", path)
		return nil
	}

	if !direct {
		logControlFallback("delegate_grant")
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	bundle, err = grantDelegationPermissionsInState(rt, state, path, permissions)
	if err != nil {
		return err
	}
	if err := rt.SaveState(state); err != nil {
		return err
	}
	if err := writeDelegationGrantBundle(bundle, outPath); err != nil {
		return err
	}
	fmt.Printf("granted delegated permissions for %s\n", path)
	return nil
}

func writeDelegationGrantBundle(bundle *joinBundle, outPath string) error {
	if bundle == nil || outPath == "" {
		return nil
	}
	if err := writeBase64JSONFile(outPath, 0o644, bundle); err != nil {
		return err
	}
	fmt.Printf("wrote authority bundle: %s\n", outPath)
	return nil
}

func grantDelegationPermissionsInState(rt *Runtime, state *stateFile, path zone.ZonePath, permissions []zone.Permission) (*joinBundle, error) {
	if state == nil || state.Network == nil {
		return nil, errors.New("state is nil")
	}
	if !path.Valid() {
		return nil, fmt.Errorf("invalid delegated zone: %s", path)
	}
	if len(permissions) == 0 {
		return nil, errors.New("at least one permission is required")
	}
	zs := state.Network.Zones[path]
	if zs == nil || zs.Authority == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	authority := cloneAuthorityForJoinBundle(zs.Authority)
	if authority == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	grantPermissionsToAuthority(authority, permissions)
	authority.Epoch++

	if path == zone.RootZone {
		if !authorityHasPrivateKey(authority, state.RootPrivateKey) {
			return nil, errors.New("root private key does not match root authority")
		}
		zs.Authority = authority
		configureValidation(state.Network)
		if err := photoncrypto.VerifyChain(state.Network, zone.RootZone, rt.Now()); err != nil {
			return nil, err
		}
		return nil, nil
	}

	parent := path.Parent()
	parentState := state.Network.Zones[parent]
	if parentState == nil || parentState.Authority == nil {
		return nil, fmt.Errorf("%w: parent %s", zone.ErrZoneNotFound, parent)
	}
	signer, err := signerForParent(state, parent)
	if err != nil {
		return nil, err
	}
	delegation := &zone.Delegation{
		ZoneName:  path,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *authority,
	}
	if err := photoncrypto.SignDelegation(delegation, parent, signer); err != nil {
		return nil, err
	}
	parentState.Delegations[path] = delegation
	zs.Authority = authority
	configureValidation(state.Network)
	if err := photoncrypto.VerifyChain(state.Network, path, rt.Now()); err != nil {
		return nil, err
	}
	rootKey, err := rootPublicKey(state.Network)
	if err != nil {
		return nil, err
	}
	bundleNetwork, err := minimalNetworkForJoinBundle(state.Network, path)
	if err != nil {
		return nil, err
	}
	configureValidation(bundleNetwork)
	if err := photoncrypto.VerifyChain(bundleNetwork, path, rt.Now()); err != nil {
		return nil, err
	}
	return &joinBundle{
		Version:       1,
		Zone:          path,
		RootPublicKey: rootKey,
		Network:       bundleNetwork,
	}, nil
}

func grantPermissionsToAuthority(authority *zone.ZoneAuthority, permissions []zone.Permission) {
	for i := range authority.Keys {
		if len(authority.Keys[i].Capabilities) == 0 {
			authority.Keys[i].Capabilities = []zone.Capability{{}}
		}
		capability := &authority.Keys[i].Capabilities[0]
		seen := map[zone.Permission]bool{}
		for _, existing := range capability.Permissions {
			seen[existing] = true
		}
		for _, perm := range permissions {
			if seen[perm] {
				continue
			}
			capability.Permissions = append(capability.Permissions, perm)
			seen[perm] = true
		}
		slices.Sort(capability.Permissions)
	}
}
