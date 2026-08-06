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
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	configureValidation(state.Network)
	if err := photoncrypto.VerifyChain(state.Network, path, rt.Now()); err != nil {
		return err
	}
	fmt.Printf("verified chain for %s\n", path)
	return nil
}
