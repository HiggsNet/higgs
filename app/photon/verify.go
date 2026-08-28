package main

import (
	"fmt"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func verifyChain(path zone.ZonePath) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if ok, err := verifyChainViaControl(rt, path); err != nil {
		return err
	} else if ok {
		fmt.Printf("verified chain for %s\n", path)
		return nil
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil || common.State.Network == nil {
		return fmt.Errorf("common state is not initialized")
	}
	configureValidation(common.State.Network)
	if err := photoncrypto.VerifyChain(common.State.Network, path, rt.Now()); err != nil {
		return err
	}
	fmt.Printf("verified chain for %s\n", path)
	return nil
}
