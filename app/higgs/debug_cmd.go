package main

import (
	"context"
	"strings"

	pingdebug "github.com/Catofes/higgs/internal/ping"
	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/urfave/cli/v3"
)

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
				Name:      "records",
				Usage:     "List active records in local state",
				UsageText: "higgs debug records [zone] [--prefix key-prefix] [--values]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "prefix", Usage: "Only show records whose key has this prefix"},
					&cli.BoolFlag{Name: "values", Usage: "Print record values"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() > 1 {
						return cli.Exit("usage: higgs debug records [zone] [--prefix key-prefix] [--values]", 1)
					}
					zoneArg := zone.ZonePath("")
					if cmd.Args().Len() == 1 {
						zoneArg = zone.ZonePath(cmd.Args().First())
					}
					return debugRecords(zoneArg, cmd.String("prefix"), cmd.Bool("values"))
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
				Name:      "links",
				Usage:     "Show IPsec link instances and reconcile state",
				UsageText: "higgs debug links [--filter peer-or-link]",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show links matching peer zone, instance id, link_id, runtime id, interface, or SA name"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() > 1 {
						return cli.Exit("usage: higgs debug links [--filter peer-or-link]", 1)
					}
					filter := cmd.String("filter")
					if cmd.Args().Len() == 1 {
						filter = cmd.Args().First()
					}
					return debugLinks(filter)
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
				Name:  "bird-dump",
				Usage: "Dump raw birdc diagnostic output from the daemon",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "netns", Usage: "Only dump the BIRD instance for this netns or instance id"},
					&cli.StringFlag{Name: "command", Aliases: []string{"c"}, Usage: "Run one birdc command instead of the default diagnostic set"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return debugBirdDump(ctx, cmd)
				},
			},
			{
				Name:  "routing-reload",
				Usage: "Trigger daemon routing reconcile",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return debugRoutingReload(ctx, cmd)
				},
			},
			{
				Name:  "routing",
				Usage: "Routing diagnostic commands",
				Commands: []*cli.Command{
					{
						Name:      "reload",
						Usage:     "Trigger daemon routing reconcile",
						UsageText: "higgs debug routing reload",
						Action: func(ctx context.Context, cmd *cli.Command) error {
							return debugRoutingReload(ctx, cmd)
						},
					},
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
			{
				Name:      "rotate-port",
				Usage:     "Manually rotate the local advertised IPsec ports",
				UsageText: "higgs debug rotate-port [--direct]",
				Description: "Ask the running daemon to force the local ipsec/ports record to the next generation. " +
					"Requires ipsec.port_mode=range, preserves the previous generation for ipsec.port_previous_grace, " +
					"and triggers sync plus firewall/IPsec reconcile. --direct writes the local DB only for recovery.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon sync or data-plane reconcile"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: higgs debug rotate-port [--direct]", 1)
					}
					return debugRotatePort(cmd.Bool("direct"))
				},
			},
			{
				Name:      "rotate",
				Usage:     "Show rotate runtime expectations and observed SAs",
				UsageText: "higgs debug rotate [--filter peer-or-link]",
				Description: "Print current and staged generation runtime names, XFRM interface ids, tunnel addresses, " +
					"stored reconcile SAs and live StrongSwan SAs for links involved in port/data-plane rotate debugging.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filter", Aliases: []string{"f"}, Usage: "Only show links matching peer zone, instance id, link_id, runtime id, interface, or SA name"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() > 1 {
						return cli.Exit("usage: higgs debug rotate [--filter peer-or-link]", 1)
					}
					filter := cmd.String("filter")
					if cmd.Args().Len() == 1 {
						filter = cmd.Args().First()
					}
					return debugRotate(ctx, filter)
				},
			},
			{
				Name:      "ping",
				Usage:     "Ping the remote StrongSwan peer over each IPsec SA for a zone",
				UsageText: "higgs debug ping <zone> [--count N] [--timeout D] [--family ipv4|ipv6] [--role active|old|staged]",
				Description: "Send ICMP echo requests to the peer tunnel address of every IPsec link instance " +
					"matching the peer zone, across IPv4/IPv6 and across both the old and new SA during a rotate. " +
					"Runs in the CLI process (requires root/CAP_NET_RAW and netns access).",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "count", Aliases: []string{"c"}, Usage: "ICMP requests per target (default 4, or health.burst)"},
					&cli.DurationFlag{Name: "timeout", Usage: "Per-request timeout (default 1s, or health.timeout)"},
					&cli.StringFlag{Name: "family", Usage: "Restrict to ipv4 or ipv6"},
					&cli.StringFlag{Name: "role", Usage: "Restrict to SA role: active, old, or staged"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: higgs debug ping <zone> [--count N] [--timeout D] [--family ipv4|ipv6] [--role active|old|staged]", 1)
					}
					return debugPing(ctx, zone.ZonePath(cmd.Args().First()), pingdebug.Options{
						Count:   cmd.Int("count"),
						Timeout: cmd.Duration("timeout"),
						Family:  strings.ToLower(strings.TrimSpace(cmd.String("family"))),
						Role:    strings.ToLower(strings.TrimSpace(cmd.String("role"))),
					})
				},
			},
		},
	}
}
