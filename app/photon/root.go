package main

import (
	"errors"
	"fmt"

	"github.com/Catofes/photon/pkg/core/zone"
)

func rootPubkey() error {
	state, err := loadState()
	if err != nil {
		return err
	}
	root := state.Network.Zones[zone.RootZone]
	if root == nil || root.Authority == nil || len(root.Authority.Keys) == 0 {
		return errors.New("root authority has no public key")
	}
	fmt.Println(formatPublicKey(root.Authority.Keys[0].Key))
	return nil
}
