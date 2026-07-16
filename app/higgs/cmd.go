package main

import (
	"context"
	"os"
	"strings"
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
			cmdAuthority(),
			cmdZone(),
			cmdRecord(),
			cmdRoute(),
			cmdIPAM(),
			cmdService(),
			cmdFirewall(),
			cmdVerify(),
			cmdVersion(),
			cmdDaemon(),
			cmdSync(),
			cmdRecovery(),
			cmdDebug(),
			cmdGC(),
			cmdDB(),
		},
	}
}

func cmdGC() *cli.Command {
	return &cli.Command{
		Name:      "gc",
		Usage:     "Garbage-collect stale local runtime state",
		UsageText: "higgs gc [--apply] [--direct]",
		Description: "Preview local runtime state that cannot be referenced by the current configuration. " +
			"Currently this removes orphan BIRD instance state only; it never stops BIRD, IPsec, or firewall resources. " +
			"Use --apply to persist the removal.",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "apply", Usage: "Actually remove the stale state; without it the command only prints a preview"},
			&cli.BoolFlag{Name: "direct", Usage: "Run in this process without contacting the daemon"},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 0 {
				return cli.Exit("usage: higgs gc [--apply] [--direct]", 1)
			}
			return garbageCollectState(cmd.Bool("apply"), cmd.Bool("direct"))
		},
	}
}

func cmdFirewall() *cli.Command {
	return &cli.Command{
		Name: "firewall", Usage: "Manage local dynamic firewall policy",
		Commands: []*cli.Command{{
			Name: "endpoint", Usage: "Manage forwarded endpoint ACLs",
			Commands: []*cli.Command{
				{
					Name: "apply", UsageText: "higgs firewall endpoint apply <name> --destination <ip> --protocol <tcp|udp> --port <port> --allow-zone <selector>...",
					Flags: []cli.Flag{
						&cli.StringFlag{Name: "destination", Required: true},
						&cli.StringFlag{Name: "protocol", Required: true},
						&cli.UintFlag{Name: "port", Required: true},
						&cli.StringSliceFlag{Name: "allow-zone", Required: true},
					},
					Action: func(ctx context.Context, cmd *cli.Command) error {
						if cmd.Args().Len() != 1 || cmd.Uint("port") > 65535 {
							return cli.Exit("invalid endpoint ACL arguments", 1)
						}
						return applyEndpointACL(cmd.Args().First(), cmd.String("destination"), cmd.String("protocol"), uint16(cmd.Uint("port")), cmd.StringSlice("allow-zone"))
					},
				},
				{
					Name: "remove", UsageText: "higgs firewall endpoint remove <name>",
					Action: func(ctx context.Context, cmd *cli.Command) error {
						if cmd.Args().Len() != 1 {
							return cli.Exit("usage: higgs firewall endpoint remove <name>", 1)
						}
						return removeEndpointACL(cmd.Args().First())
					},
				},
				{
					Name: "list", UsageText: "higgs firewall endpoint list",
					Action: func(ctx context.Context, cmd *cli.Command) error {
						if cmd.Args().Len() != 0 {
							return cli.Exit("usage: higgs firewall endpoint list", 1)
						}
						return listEndpointACLs()
					},
				},
			},
		}},
	}
}

func cmdService() *cli.Command {
	return &cli.Command{
		Name:  "service",
		Usage: "Publish and withdraw signed application service records",
		Commands: []*cli.Command{
			{
				Name:      "publish",
				Usage:     "Publish a SOCKS5 endpoint owned by the managed zone",
				UsageText: "higgs service publish --endpoint <region,address,port>... [--direct]",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{Name: "endpoint", Usage: "Endpoint as region,address,port; repeat for multiple networks"},
					&cli.StringFlag{Name: "region", Usage: "Legacy single-endpoint region"},
					&cli.StringFlag{Name: "address", Usage: "Legacy single-endpoint address"},
					&cli.UintFlag{Name: "port", Value: 3128},
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 || cmd.Uint("port") > 65535 {
						return cli.Exit("usage: higgs service publish --endpoint <region,address,port>...", 1)
					}
					endpoints, err := parseSOCKS5EndpointFlags(cmd.StringSlice("endpoint"), cmd.String("region"), cmd.String("address"), uint16(cmd.Uint("port")))
					if err != nil {
						return err
					}
					return publishSOCKS5Endpoints(endpoints, cmd.Bool("direct"))
				},
			},
			{
				Name:      "withdraw",
				Usage:     "Withdraw a previously published SOCKS5 endpoint",
				UsageText: "higgs service withdraw [--direct]",
				Flags:     []cli.Flag{&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly"}},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: higgs service withdraw [--direct]", 1)
					}
					return withdrawSOCKS5Service(cmd.Bool("direct"))
				},
			},
		},
	}
}

func cmdVersion() *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "Show build version information",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 0 {
				return cli.Exit("usage: higgs version", 1)
			}
			return writeVersion(os.Stdout)
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
				UsageText: "higgs join accept [--direct] <bundle-b64|bundle-file> [key.json]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without contacting the daemon"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 || cmd.Args().Len() > 2 {
						return cli.Exit("usage: higgs join accept <bundle-b64|bundle-file> [key.json]", 1)
					}
					return acceptJoinBundle(cmd.Args().Get(0), cmd.Args().Get(1), cmd.Bool("direct"))
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
				UsageText: "higgs delegate issue [--cap <permissions>] [--direct] <request-b64|request-file> [bundle.b64]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "cap", Usage: "Comma-separated permissions for the delegated authority"},
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without contacting the daemon"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 || cmd.Args().Len() > 2 {
						return cli.Exit("usage: higgs delegate issue <request-b64|request-file> [bundle.b64]", 1)
					}
					permissions, err := parseOptionalAuthorityPermissions(cmd.String("cap"))
					if err != nil {
						return err
					}
					return issueDelegation(cmd.Args().Get(0), cmd.Args().Get(1), permissions, cmd.Bool("direct"))
				},
			},
			{
				Name:      "revoke",
				Usage:     "Revoke a child zone delegation",
				UsageText: "higgs delegate revoke [--direct] <zone> [reason]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without contacting the daemon"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 || cmd.Args().Len() > 2 {
						return cli.Exit("usage: higgs delegate revoke <zone> [reason]", 1)
					}
					reason := ""
					if cmd.Args().Len() == 2 {
						reason = cmd.Args().Get(1)
					}
					return revokeDelegation(zone.ZonePath(cmd.Args().Get(0)), reason, cmd.Bool("direct"))
				},
			},
		},
	}
}

func cmdAuthority() *cli.Command {
	return &cli.Command{
		Name:  "authority",
		Usage: "Zone authority management commands",
		Commands: []*cli.Command{
			{
				Name:      "grant",
				Usage:     "Grant permissions to an existing authority",
				UsageText: "higgs authority grant [--direct] <zone> <permission>[,<permission>...] [bundle.b64]",
				Description: "Increase the target authority epoch and add permissions to its authorized keys.\n" +
					"For non-root zones this must be run by the parent zone admin because the parent delegation is re-signed.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without contacting the daemon"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 2 || cmd.Args().Len() > 3 {
						return cli.Exit("usage: higgs authority grant <zone> <permission>[,<permission>...] [bundle.b64]", 1)
					}
					permissions, err := parseAuthorityPermissions([]string{cmd.Args().Get(1)})
					if err != nil {
						return err
					}
					return grantAuthority(zone.ZonePath(cmd.Args().Get(0)), permissions, cmd.Args().Get(2), cmd.Bool("direct"))
				},
			},
		},
	}
}

func parseOptionalAuthorityPermissions(raw string) ([]zone.Permission, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	return parseAuthorityPermissions([]string{raw})
}

func cmdZone() *cli.Command {
	return &cli.Command{
		Name:  "zone",
		Usage: "Zone inspection commands",
		Commands: []*cli.Command{
			{
				Name:      "show",
				Usage:     "Show zone details as JSON",
				UsageText: "higgs zone show <zone> [--history]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "history", Usage: "Include bounded record history"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: higgs zone show <zone> [--history]", 1)
					}
					return showZone(zone.ZonePath(cmd.Args().First()), cmd.Bool("history"))
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
				UsageText: "higgs record put [--direct] <zone> <key> <value> [type]",
				Description: "Store a key-value record in the specified zone.\n" +
					"Optional type defaults to 'policy.string'.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without contacting the daemon"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 3 || cmd.Args().Len() > 4 {
						return cli.Exit("usage: higgs record put <zone> <key> <value> [type]", 1)
					}
					recordType := "policy.string"
					if cmd.Args().Len() > 3 {
						recordType = cmd.Args().Get(3)
					}
					return putRecord(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), []byte(cmd.Args().Get(2)), recordType, cmd.Bool("direct"))
				},
			},
			{
				Name:      "get",
				Usage:     "Get a record from a zone as JSON",
				UsageText: "higgs record get <zone> <key> [--history=N]",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "history", Usage: "Include up to N previous versions in record_history"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: higgs record get <zone> <key>", 1)
					}
					return getRecord(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Int("history"))
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
				UsageText: "higgs route announce [--direct] <zone> <prefix>",
				Description: "Announce a CIDR prefix from the specified zone.\n" +
					"The prefix is canonicalized before storage (e.g. 10.0.1.1/24 becomes 10.0.1.0/24).",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon routing reconcile"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: higgs route announce <zone> <prefix>", 1)
					}
					return announceRoute(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Bool("direct"))
				},
			},
			{
				Name:      "withdraw",
				Usage:     "Withdraw a route prefix",
				UsageText: "higgs route withdraw [--direct] <zone> <prefix>",
				Description: "Withdraw a previously announced CIDR prefix from the specified zone.\n" +
					"The prefix is canonicalized before lookup.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon routing reconcile"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: higgs route withdraw <zone> <prefix>", 1)
					}
					return withdrawRoute(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Bool("direct"))
				},
			},
			{
				Name:      "show",
				Usage:     "Show route announcements",
				UsageText: "higgs route show [--zone <zone>] [--all] [--json]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "zone", Usage: "Filter by announcing zone"},
					&cli.BoolFlag{Name: "all", Usage: "Include withdrawn announcements"},
					&cli.BoolFlag{Name: "json", Usage: "Print structured JSON output"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: higgs route show [--zone <zone>] [--all] [--json]", 1)
					}
					return showRoutes(zone.ZonePath(cmd.String("zone")), cmd.Bool("all"), cmd.Bool("json"))
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
