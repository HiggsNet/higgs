package main

import (
	"context"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/urfave/cli/v3"
)

func cmdJoin() *cli.Command {
	return &cli.Command{
		Name:  "join",
		Usage: "Join request and acceptance commands",
		Commands: []*cli.Command{
			{
				Name:      "request",
				Usage:     "Create a join request for a zone",
				UsageText: "higgs join request <zone> <key.json> <request.json>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 3 {
						return cli.Exit("usage: higgs join request <zone> <key.json> <request.json>", 1)
					}
					return createJoinRequest(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Args().Get(2))
				},
			},
			{
				Name:      "accept",
				Usage:     "Accept a join bundle",
				UsageText: "higgs join accept <bundle.json> <key.json>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: higgs join accept <bundle.json> <key.json>", 1)
					}
					return acceptJoinBundle(cmd.Args().Get(0), cmd.Args().Get(1))
				},
			},
		},
	}
}
