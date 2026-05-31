package main

import (
	"context"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/urfave/cli/v3"
)

func rootCommand() *cli.Command {
	return &cli.Command{
		Name:        "higgs",
		Usage:       "Higgs zone authority CLI",
		Description: "A command-line tool for managing Higgs zones, keys, records, and sync.",
		Commands: []*cli.Command{
			cmdInit(),
			cmdRoot(),
			cmdKeygen(),
			cmdJoin(),
			cmdDelegate(),
			cmdZone(),
			cmdRecord(),
			cmdVerify(),
			cmdSync(),
			cmdDB(),
		},
	}
}

func cmdInit() *cli.Command {
	return &cli.Command{
		Name:      "init",
		Usage:     "Initialize a new local state file",
		UsageText: "higgs init [ZONE]",
		Description: "Initialize a new state database with the given managed zone.\n" +
			"If ZONE is omitted, defaults to 'local.'.",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() > 1 {
				return cli.Exit("usage: higgs init [ZONE]", 1)
			}
			managedZone := zone.ZonePath("local.")
			if cmd.Args().Len() > 0 {
				managedZone = zone.ZonePath(cmd.Args().First())
			}
			return initState(managedZone)
		},
	}
}

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
					return rootPubkey()
				},
			},
		},
	}
}

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

func cmdSync() *cli.Command {
	return &cli.Command{
		Name:  "sync",
		Usage: "Gossip sync commands",
		Commands: []*cli.Command{
			{
				Name:        "status",
				Usage:       "Show sync and peer status",
				Description: "Display current sync configuration, known peers, and zone digests.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return syncStatus()
				},
			},
			{
				Name:        "serve",
				Usage:       "Start the gossip sync server",
				Description: "Listen for incoming sync messages and respond to pings/pongs.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return syncServe()
				},
			},
			{
				Name:      "once",
				Usage:     "Run a single sync round with a peer",
				UsageText: "higgs sync once <peer-id>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: higgs sync once <peer-id>", 1)
					}
					return syncOnce(cmd.Args().First())
				},
			},
		},
	}
}

func cmdDB() *cli.Command {
	return &cli.Command{
		Name:  "db",
		Usage: "Low-level database inspection commands",
		Commands: []*cli.Command{
			{
				Name:      "dump",
				Usage:     "Dump all database buckets and keys",
				UsageText: "higgs db dump [zone]",
				Description: "Print every bucket and key in the state database.\n" +
					"If a zone is provided, only that zone bucket is shown (plus meta).",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() > 1 {
						return cli.Exit("usage: higgs db dump [zone]", 1)
					}
					filter := ""
					if cmd.Args().Len() > 0 {
						filter = cmd.Args().First()
					}
					return dbDump(filter)
				},
			},
			{
				Name:        "stats",
				Usage:       "Show database bucket statistics",
				Description: "Print the number of keys and total size per bucket.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: higgs db stats", 1)
					}
					return dbStats()
				},
			},
		},
	}
}
