package main

import (
	"context"
	"time"

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
			cmdRoute(),
			cmdIPAM(),
			cmdVerify(),
			cmdDaemon(),
			cmdSync(),
			cmdDebug(),
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
				UsageText: "higgs join request <zone> <key.json> [request.b64]\n   higgs join request --from-config [request.b64]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "from-config", Usage: "Create the request from managed_zone and identity.key_path in config.yaml"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Bool("from-config") {
						if cmd.Args().Len() > 1 {
							return cli.Exit("usage: higgs join request --from-config [request.b64]", 1)
						}
						return writeJoinRequestFromConfig(cmd.Args().First())
					}
					if cmd.Args().Len() < 2 || cmd.Args().Len() > 3 {
						return cli.Exit("usage: higgs join request <zone> <key.json> [request.b64]", 1)
					}
					return createJoinRequest(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Args().Get(2))
				},
			},
			{
				Name:      "accept",
				Usage:     "Accept a join bundle",
				UsageText: "higgs join accept <bundle-b64|bundle-file> <key.json>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: higgs join accept <bundle-b64|bundle-file> <key.json>", 1)
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
				UsageText: "higgs delegate issue <request-b64|request-file> [bundle.b64]",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 || cmd.Args().Len() > 2 {
						return cli.Exit("usage: higgs delegate issue <request-b64|request-file> [bundle.b64]", 1)
					}
					return issueDelegation(cmd.Args().Get(0), cmd.Args().Get(1))
				},
			},
			{
				Name:      "revoke",
				Usage:     "Revoke a child zone delegation",
				UsageText: "higgs delegate revoke <zone> [reason]",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 || cmd.Args().Len() > 2 {
						return cli.Exit("usage: higgs delegate revoke <zone> [reason]", 1)
					}
					reason := ""
					if cmd.Args().Len() == 2 {
						reason = cmd.Args().Get(1)
					}
					return revokeDelegation(zone.ZonePath(cmd.Args().Get(0)), reason)
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

func cmdRoute() *cli.Command {
	return &cli.Command{
		Name:  "route",
		Usage: "Route announcement commands",
		Commands: []*cli.Command{
			{
				Name:      "announce",
				Usage:     "Announce a route prefix",
				UsageText: "higgs route announce <zone> <prefix>",
				Description: "Announce a CIDR prefix from the specified zone.\n" +
					"The prefix is canonicalized before storage (e.g. 10.0.1.1/24 becomes 10.0.1.0/24).",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: higgs route announce <zone> <prefix>", 1)
					}
					return announceRoute(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1))
				},
			},
			{
				Name:      "withdraw",
				Usage:     "Withdraw a route prefix",
				UsageText: "higgs route withdraw <zone> <prefix>",
				Description: "Withdraw a previously announced CIDR prefix from the specified zone.\n" +
					"The prefix is canonicalized before lookup.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: higgs route withdraw <zone> <prefix>", 1)
					}
					return withdrawRoute(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1))
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

func cmdDaemon() *cli.Command {
	return &cli.Command{
		Name:        "daemon",
		Usage:       "Run the local Higgs daemon",
		Description: "Run gossip serving and periodic outbound sync through the Phase 3 daemon service.",
		Flags: []cli.Flag{
			&cli.IntFlag{Name: "interval", Value: int(defaultDaemonInterval.Seconds()), Usage: "Outbound sync interval in seconds"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 0 {
				return cli.Exit("usage: higgs daemon [--interval seconds]", 1)
			}
			return daemonRun(ctx, time.Duration(cmd.Int("interval"))*time.Second)
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
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "Show bootstrap and allowlist details"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return syncStatus(cmd.Bool("verbose"))
				},
			},
			{
				Name:        "serve",
				Usage:       "Start the gossip sync server",
				Description: "Listen for incoming sync messages and respond to pings/pongs.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return syncServe(ctx)
				},
			},
			{
				Name:        "run",
				Usage:       "Run gossip serving and periodic outbound sync",
				Description: "Listen for incoming sync messages while periodically syncing bootstrap peers.",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "interval", Value: 5, Usage: "Outbound sync interval in seconds"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return syncRun(ctx, time.Duration(cmd.Int("interval"))*time.Second)
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

func cmdDebug() *cli.Command {
	return &cli.Command{
		Name:  "debug",
		Usage: "Diagnostic inspection commands",
		Commands: []*cli.Command{
			{
				Name:      "peer",
				Usage:     "Show diagnostic state for a peer",
				UsageText: "higgs debug peer <peer-id>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: higgs debug peer <peer-id>", 1)
					}
					return debugPeer(cmd.Args().First())
				},
			},
			{
				Name:      "zone",
				Usage:     "Show diagnostic state for a zone",
				UsageText: "higgs debug zone <zone>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: higgs debug zone <zone>", 1)
					}
					return debugZone(zone.ZonePath(cmd.Args().First()))
				},
			},
			{
				Name:  "endpoints",
				Usage: "Show local endpoint candidates and discovered peer endpoints",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return debugEndpoints()
				},
			},
			{
				Name:  "links",
				Usage: "Show IPsec link instances and reconcile state",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return debugLinks()
				},
			},
			{
				Name:  "babel",
				Usage: "Show BIRD/Babel routing instance state",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return debugBabel(ctx, cmd)
				},
			},
			{
				Name:  "routes",
				Usage: "Show authorized route set",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return debugRoutes(ctx, cmd)
				},
			},
			{
				Name:      "route",
				Usage:     "Explain a specific route prefix",
				UsageText: "higgs debug route <prefix>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: higgs debug route <prefix>", 1)
					}
					return debugRoute(ctx, cmd)
				},
			},
			{
				Name:  "admission",
				Usage: "Show auto-join admission diagnostics",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return debugAdmission()
				},
			},
			{
				Name:  "firewall",
				Usage: "Show firewall reconcile state and owned objects",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return debugFirewall(ctx, cmd)
				},
			},
			{
				Name:  "peers",
				Usage: "Show dynamic peer management lifecycle status",
				Description: "Display the derived lifecycle state of every known peer.\n" +
					"States include: eligible, discovered, connecting, active, stale, offline, policy_denied, config_error, revoked.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return debugPeers(ctx)
				},
			},
			{
				Name:  "revoke-impact",
				Usage: "Show revocation impact and cleanup status for revoked zones",
				Description: "Display the affected subtree, link instances, sync peers, " +
					"configured-but-revoked peers, IPAM prefixes and per-layer cleanup status " +
					"for every currently-revoked zone.",
				UsageText: "higgs debug revoke-impact [zone]",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					zoneArg := ""
					if cmd.Args().Len() > 0 {
						zoneArg = cmd.Args().First()
					}
					return debugRevokeImpact(ctx, zoneArg)
				},
			},
			{
				Name:        "health",
				Usage:       "Show link health probe state",
				Description: "Display per-link health state, probe RTT/loss/jitter and rotate cutover gate.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return debugHealth()
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
