package main

import (
	"context"

	"github.com/urfave/cli/v3"
)

func cmdDelegate() *cli.Command {
	return &cli.Command{
		Name:  "delegate",
		Usage: "Delegation management commands",
		Commands: []*cli.Command{
			{
				Name:      "issue",
				Usage:     "Issue a delegation from a join request",
				UsageText: "higgs delegate issue <request.json> <bundle.json>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: higgs delegate issue <request.json> <bundle.json>", 1)
					}
					return issueDelegation(cmd.Args().Get(0), cmd.Args().Get(1))
				},
			},
		},
	}
}
