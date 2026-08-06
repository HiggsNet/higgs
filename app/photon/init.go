package main

import (
	"crypto/ed25519"
	"fmt"

	"github.com/Catofes/photon/pkg/core/zone"
	photoncrypto "github.com/Catofes/photon/pkg/crypto"
)

func initRootState() error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if rootPub, controlled, err := initRootViaControl(rt); err != nil {
		return err
	} else if controlled {
		fmt.Printf("initialized root via daemon in %s\n", rt.StatePath)
		fmt.Printf("root public key: %s\n", formatPublicKey(rootPub))
		return nil
	}
	rootPub, err := initRootStateInRuntime(rt)
	if err != nil {
		return err
	}
	fmt.Printf("initialized root in %s\n", rt.StatePath)
	fmt.Printf("root public key: %s\n", formatPublicKey(rootPub))
	return nil
}

func initRootStateInRuntime(rt *Runtime) (ed25519.PublicKey, error) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: photoncrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key:          rootPub,
			Capabilities: defaultRootCapabilities(),
		}},
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	state := &stateFile{
		ManagedZone:    zone.RootZone,
		RootPrivateKey: rootPriv,
		Network:        ns,
	}
	if err := rt.SaveState(state); err != nil {
		return nil, err
	}
	return rootPub, nil
}
