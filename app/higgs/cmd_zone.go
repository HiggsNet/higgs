package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/urfave/cli/v3"
)

func cmdZone() *cli.Command {
	return &cli.Command{
		Name:  "zone",
		Usage: "Zone inspection commands",
		Commands: []*cli.Command{
			{
				Name:      "show",
				Usage:     "Show zone details as JSON",
				UsageText: "higgs zone show <zone>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: higgs zone show <zone>", 1)
					}
					return showZone(zone.ZonePath(cmd.Args().First()))
				},
			},
		},
	}
}

func showZone(path zone.ZonePath) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	zs := state.Network.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(zs)
}
