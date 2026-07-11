package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func allAuthorityPermissions() []zone.Permission {
	return []zone.Permission{
		zone.PermWrite,
		zone.PermWriteWireGuard,
		zone.PermWriteRoute,
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
		for _, part := range strings.Split(raw, ",") {
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
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func parseAuthorityPermission(raw string) (zone.Permission, error) {
	switch zone.Permission(raw) {
	case zone.PermWrite, zone.PermWriteWireGuard, zone.PermWriteRoute, zone.PermDelegate, zone.PermAllocateIP:
		return zone.Permission(raw), nil
	default:
		return "", fmt.Errorf("unsupported authority permission %q", raw)
	}
}

func grantAuthority(path zone.ZonePath, permissions []zone.Permission, outPath string, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	bundle, controlled, err := grantAuthorityViaControl(rt, path, permissions)
	if err != nil {
		return err
	}
	if controlled {
		if err := writeAuthorityGrantBundle(bundle, outPath); err != nil {
			return err
		}
		fmt.Printf("granted authority permissions for %s via daemon\n", path)
		return nil
	}

	if !direct {
		logControlFallback("authority_grant")
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	bundle, err = grantAuthorityInState(rt, state, path, permissions)
	if err != nil {
		return err
	}
	if err := rt.SaveState(state); err != nil {
		return err
	}
	if err := writeAuthorityGrantBundle(bundle, outPath); err != nil {
		return err
	}
	fmt.Printf("granted authority permissions for %s\n", path)
	return nil
}

func writeAuthorityGrantBundle(bundle *joinBundle, outPath string) error {
	if bundle == nil || outPath == "" {
		return nil
	}
	if err := writeBase64JSONFile(outPath, 0o644, bundle); err != nil {
		return err
	}
	fmt.Printf("wrote authority bundle: %s\n", outPath)
	return nil
}

func grantAuthorityInState(rt *Runtime, state *stateFile, path zone.ZonePath, permissions []zone.Permission) (*joinBundle, error) {
	if state == nil || state.Network == nil {
		return nil, errors.New("state is nil")
	}
	if !path.Valid() {
		return nil, fmt.Errorf("invalid authority zone: %s", path)
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
		if err := higgscrypto.VerifyChain(state.Network, zone.RootZone, rt.Now()); err != nil {
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
	if err := higgscrypto.SignDelegation(delegation, parent, signer); err != nil {
		return nil, err
	}
	parentState.Delegations[path] = delegation
	zs.Authority = authority
	configureValidation(state.Network)
	if err := higgscrypto.VerifyChain(state.Network, path, rt.Now()); err != nil {
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
	if err := higgscrypto.VerifyChain(bundleNetwork, path, rt.Now()); err != nil {
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
		sort.Slice(capability.Permissions, func(i, j int) bool {
			return capability.Permissions[i] < capability.Permissions[j]
		})
	}
}
