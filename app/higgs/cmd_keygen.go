package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"
)

func cmdKeygen() *cli.Command {
	return &cli.Command{
		Name:      "keygen",
		Usage:     "Generate a new Ed25519 key pair",
		UsageText: "higgs keygen <file>",
		Description: "Generate a new Ed25519 private key and write it to the specified JSON file.\n" +
			"The public key is printed to stdout.",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 1 {
				return cli.Exit("usage: higgs keygen <file>", 1)
			}
			return keygen(cmd.Args().First())
		},
	}
}

func keygen(path string) error {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	key := privateKeyFile{
		Type:       "higgs.ed25519.private.v1",
		PublicKey:  pub,
		PrivateKey: priv,
	}
	if err := writeJSONFile(path, 0o600, &key); err != nil {
		return err
	}
	fmt.Printf("wrote key: %s\n", path)
	fmt.Printf("public key: %s\n", formatPublicKey(pub))
	return nil
}

func writeJSONFile(path string, mode os.FileMode, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, mode)
}
