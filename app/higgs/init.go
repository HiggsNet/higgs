package main

import (
	"crypto/ed25519"
	"fmt"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func initRootState() error {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: higgscrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	state := &stateFile{
		ManagedZone:    zone.RootZone,
		RootPrivateKey: rootPriv,
		Network:        ns,
	}
	if err := saveState(state); err != nil {
		return err
	}
	path, err := configuredStatePath()
	if err != nil {
		return err
	}
	fmt.Printf("initialized root in %s\n", path)
	fmt.Printf("root public key: %s\n", formatPublicKey(rootPub))
	return nil
}

func initState(managedZone zone.ZonePath) error {
	if !managedZone.Valid() || managedZone == zone.RootZone {
		return fmt.Errorf("invalid managed zone: %s", managedZone)
	}

	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	zonePub, zonePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: higgscrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	chain := zoneChain(managedZone)
	for i, path := range chain {
		authority := &zone.ZoneAuthority{
			Zone:      path,
			Epoch:     1,
			Threshold: higgscrypto.SupportedThreshold,
			Keys: []zone.AuthorizedKey{{
				Key: zonePub,
				Capabilities: []zone.Capability{{
					Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate},
				}},
			}},
		}
		ns.Zones[path] = zone.NewZoneState(path, authority)

		parent := zone.RootZone
		signer := rootPriv
		if i > 0 {
			parent = chain[i-1]
			signer = zonePriv
		}
		delegation := &zone.Delegation{
			ZoneName:  path,
			Scope:     zone.DelegationScopeDirectChild,
			Authority: *authority,
		}
		if err := higgscrypto.SignDelegation(delegation, parent, signer); err != nil {
			return err
		}
		ns.Zones[parent].Delegations[path] = delegation
	}

	state := &stateFile{
		ManagedZone:    managedZone,
		RootPrivateKey: rootPriv,
		ZonePrivateKey: zonePriv,
		Network:        ns,
	}
	if err := saveState(state); err != nil {
		return err
	}
	path, err := configuredStatePath()
	if err != nil {
		return err
	}
	fmt.Printf("initialized %s in %s\n", managedZone, path)
	fmt.Printf("root public key: %s\n", formatPublicKey(rootPub))
	return nil
}
