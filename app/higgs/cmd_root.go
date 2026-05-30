package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/urfave/cli/v3"
)

func cmdRoot() *cli.Command {
	return &cli.Command{
		Name:  "root",
		Usage: "Root zone management commands",
		Commands: []*cli.Command{
			{
				Name:        "init",
				Usage:       "Initialize a root state file",
				Description: "Create a new state database containing only the root zone.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: higgs root init", 1)
					}
					return initRootState()
				},
			},
			{
				Name:        "pubkey",
				Usage:       "Show the root zone public key",
				Description: "Display the public key of the root zone authority.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: higgs root pubkey", 1)
					}
					state, err := loadState()
					if err != nil {
						return err
					}
					root := state.Network.Zones[zone.RootZone]
					if root == nil || root.Authority == nil || len(root.Authority.Keys) == 0 {
						return errors.New("root authority has no public key")
					}
					fmt.Println(hex.EncodeToString(root.Authority.Keys[0].Key))
					return nil
				},
			},
		},
	}
}
