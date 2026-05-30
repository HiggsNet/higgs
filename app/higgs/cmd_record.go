package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"github.com/urfave/cli/v3"
)

func cmdRecord() *cli.Command {
	return &cli.Command{
		Name:  "record",
		Usage: "Record management commands",
		Commands: []*cli.Command{
			{
				Name:      "put",
				Usage:     "Store a record in a zone",
				UsageText: "higgs record put <zone> <key> <value> [type]",
				Description: "Store a key-value record in the specified zone.\n" +
					"Optional type defaults to 'policy.string'.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 3 || cmd.Args().Len() > 4 {
						return cli.Exit("usage: higgs record put <zone> <key> <value> [type]", 1)
					}
					recordType := "policy.string"
					if cmd.Args().Len() > 3 {
						recordType = cmd.Args().Get(3)
					}
					return putRecord(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), []byte(cmd.Args().Get(2)), recordType)
				},
			},
		},
	}
}

func putRecord(path zone.ZonePath, key string, value []byte, recordType string) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	configureValidation(state.Network)

	zs := state.Network.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	current := zs.Records[key]
	record := &zone.Record{
		Zone:      path,
		Key:       key,
		Type:      recordType,
		Value:     value,
		Version:   1,
		Timestamp: time.Now().Unix(),
	}
	if current != nil {
		record.Version = current.Version + 1
		record.PrevHash = higgscrypto.RecordHash(current)
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		return err
	}
	if err := state.Network.Put(record); err != nil {
		return err
	}
	if err := saveState(state); err != nil {
		return err
	}
	fmt.Printf("put %s/%s version %d\n", path, key, record.Version)
	return nil
}
