package main

import (
	"fmt"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func verifyChain(path zone.ZonePath) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	configureValidation(state.Network)
	if err := higgscrypto.VerifyChain(state.Network, path, time.Now()); err != nil {
		return err
	}
	fmt.Printf("verified chain for %s\n", path)
	return nil
}
