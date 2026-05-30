package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"github.com/urfave/cli/v3"
)

func cmdVerify() *cli.Command {
	return &cli.Command{
		Name:      "verify",
		Usage:     "Verify zone chain integrity",
		UsageText: "higgs verify [chain] <zone>",
		Description: "Verify the delegation chain for a zone.\n" +
			"The optional 'chain' keyword is accepted for compatibility.",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			switch cmd.Args().Len() {
			case 1:
				return verifyChain(zone.ZonePath(cmd.Args().First()))
			case 2:
				if cmd.Args().First() != "chain" {
					return cli.Exit("usage: higgs verify [chain] <zone>", 1)
				}
				return verifyChain(zone.ZonePath(cmd.Args().Get(1)))
			default:
				return cli.Exit("usage: higgs verify [chain] <zone>", 1)
			}
		},
	}
}

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
