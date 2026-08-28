package main

import (
	"errors"
	"fmt"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func rootPubkey() error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := daemonStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		if len(response.RootPublicKey) == 0 {
			return errors.New("root authority has no public key")
		}
		fmt.Println(formatPublicKey(response.RootPublicKey))
		return nil
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil || common.State.Network == nil {
		return errors.New("common state is not initialized")
	}
	root := common.State.Network.Zones[zone.RootZone]
	if root == nil || root.Authority == nil || len(root.Authority.Keys) == 0 {
		return errors.New("root authority has no public key")
	}
	fmt.Println(formatPublicKey(root.Authority.Keys[0].Key))
	return nil
}
