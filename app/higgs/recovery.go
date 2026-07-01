package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"github.com/urfave/cli/v3"
)

func cmdRecovery() *cli.Command {
	return &cli.Command{
		Name:  "recovery",
		Usage: "Explicit state recovery commands",
		Commands: []*cli.Command{
			{
				Name:      "export-zone",
				Usage:     "Export a signed zone snapshot to a file or stdout",
				UsageText: "higgs recovery export-zone <zone> [snapshot.b64]",
				Description: "Export the active ZoneSnapshot from the local state as base64 JSON.\n" +
					"This is useful when an offline root/admin node needs to carry signed records to an online peer.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() < 1 || cmd.Args().Len() > 2 {
						return cli.Exit("usage: higgs recovery export-zone <zone> [snapshot.b64]", 1)
					}
					return recoveryExportZone(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1))
				},
			},
			{
				Name:      "import-zone",
				Usage:     "Import a signed zone snapshot from a file or payload",
				UsageText: "higgs recovery import-zone <snapshot-b64|snapshot-file>",
				Description: "Import a signed ZoneSnapshot into the local state after normal signature and delegation-chain verification.\n" +
					"This accepts snapshots created by recovery export-zone.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: higgs recovery import-zone <snapshot-b64|snapshot-file>", 1)
					}
					return recoveryImportZone(cmd.Args().First())
				},
			},
			{
				Name:      "pull-zone",
				Usage:     "Recover a signed zone snapshot from a peer",
				UsageText: "higgs recovery pull-zone <zone> --from <peer-id>",
				Description: "Pull a ZoneSnapshot over object-pull TCP and apply it after normal signature and delegation-chain verification.\n" +
					"This explicit recovery path may restore this node's managed zone, unlike ordinary gossip sync.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "from", Usage: "Peer ID to pull the snapshot from", Required: true},
					&cli.IntFlag{Name: "timeout", Value: 5, Usage: "Recovery pull timeout in seconds"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: higgs recovery pull-zone <zone> --from <peer-id>", 1)
					}
					timeout := time.Duration(cmd.Int("timeout")) * time.Second
					return recoveryPullZone(ctx, zone.ZonePath(cmd.Args().First()), cmd.String("from"), timeout)
				},
			},
			{
				Name:        "pull-chain",
				Usage:       "Recover a zone and its ancestor chain from a peer",
				UsageText:   "higgs recovery pull-chain <zone> --from <peer-id>",
				Description: "Pull root-to-zone snapshots in trust-chain order, so deeper delegated zones can be recovered from an empty bootstrap DB.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "from", Usage: "Peer ID to pull snapshots from", Required: true},
					&cli.IntFlag{Name: "timeout", Value: 5, Usage: "Total recovery pull timeout in seconds"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: higgs recovery pull-chain <zone> --from <peer-id>", 1)
					}
					timeout := time.Duration(cmd.Int("timeout")) * time.Second
					return recoveryPullChain(ctx, zone.ZonePath(cmd.Args().First()), cmd.String("from"), timeout)
				},
			},
			{
				Name:      "cleanup-ipsec",
				Usage:     "Tear down locally managed IPsec links",
				UsageText: "higgs recovery cleanup-ipsec",
				Description: "Explicitly terminate Higgs-managed StrongSwan connections and delete their XFRM interfaces.\n" +
					"This is intended for local recovery after system networking state becomes inconsistent.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: higgs recovery cleanup-ipsec", 1)
					}
					return recoveryCleanupIPsec(ctx)
				},
			},
			{
				Name:      "purge-revoked",
				Usage:     "Remove revoked zones' local residue (dry-run by default)",
				UsageText: "higgs recovery purge-revoked [--zone <zone>] [--apply]",
				Description: "Hard-delete the local residue of revoked zones: their ZoneState bodies in the DB, " +
					"plus LinkInstances and SyncPeers entries pointing at them.\n" +
					"Without --apply this only prints a preview and changes nothing. " +
					"Without --zone every currently-revoked zone is targeted; with --zone only that zone " +
					"(which must be revoked) and its descendant subtree are targeted. " +
					"Parent revocation tombstones are always preserved so revoked names cannot be re-delegated " +
					"at a stale epoch, and the local node's own managed-zone identity chain is never touched.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "zone", Usage: "Limit the purge to a single revoked zone (and its subtree)"},
					&cli.BoolFlag{Name: "apply", Usage: "Actually delete; without it the command only prints a preview"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: higgs recovery purge-revoked [--zone <zone>] [--apply]", 1)
					}
					return recoveryPurgeRevoked(cmd.Bool("apply"), zone.ZonePath(cmd.String("zone")))
				},
			},
		},
	}
}

func recoveryExportZone(path zone.ZonePath, outPath string) error {
	if !path.Valid() {
		return zone.ErrInvalidZonePath
	}
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	snapshot, err := gossip.Snapshot(state.Network, path)
	if err != nil {
		return err
	}
	if outPath == "" {
		text, err := encodeBase64JSON(snapshot)
		if err != nil {
			return err
		}
		fmt.Println(text)
		return nil
	}
	if err := writeBase64JSONFile(outPath, 0o644, snapshot); err != nil {
		return err
	}
	fmt.Printf("exported zone %s snapshot: %s\n", path, outPath)
	return nil
}

func recoveryImportZone(input string) error {
	var snapshot gossip.ZoneSnapshot
	if err := readBase64JSONOrJSON(input, &snapshot); err != nil {
		return err
	}
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if result, revocations, ok, err := importRecoveryZoneViaControl(rt, &snapshot); err != nil {
		return err
	} else if ok {
		printRecoveryImportResult(result, revocations, " via daemon")
		return nil
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	state.Lock()
	defer state.Unlock()
	result, err := applyRecoveryZoneSnapshot(rt, state, &snapshot)
	if err != nil {
		return err
	}
	if err := rt.SaveState(state); err != nil {
		return err
	}
	revocations := 0
	if zs := state.Network.Zones[result.Zone]; zs != nil {
		revocations = len(zs.Revocations)
	}
	printRecoveryImportResult(result, revocations, "")
	return nil
}

func printRecoveryImportResult(result *gossip.ApplyResult, revocations int, suffix string) {
	fmt.Printf("imported zone %s snapshot%s: records_applied=%d delegations=%d revocations=%d\n",
		result.Zone, suffix, result.Records, result.Delegation, revocations)
}

func recoveryPullZone(ctx context.Context, path zone.ZonePath, peerID string, timeout time.Duration) error {
	if !path.Valid() {
		return zone.ErrInvalidZonePath
	}
	if peerID == "" {
		return errors.New("recovery peer is required")
	}
	if timeout <= 0 {
		return errors.New("recovery timeout must be positive")
	}
	return recoveryPullZones(ctx, []zone.ZonePath{path}, peerID, timeout)
}

func recoveryPullChain(ctx context.Context, path zone.ZonePath, peerID string, timeout time.Duration) error {
	if !path.Valid() {
		return zone.ErrInvalidZonePath
	}
	return recoveryPullZones(ctx, recoveryChainZones(path), peerID, timeout)
}

func recoveryPullZones(ctx context.Context, paths []zone.ZonePath, peerID string, timeout time.Duration) error {
	if len(paths) == 0 {
		return errors.New("recovery zone is required")
	}
	if peerID == "" {
		return errors.New("recovery peer is required")
	}
	if timeout <= 0 {
		return errors.New("recovery timeout must be positive")
	}
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	config, err := rt.SyncConfig(state)
	if err != nil {
		return err
	}

	state.Lock()
	defer state.Unlock()

	deadline := time.Now().Add(timeout)
	results := make([]*gossip.ApplyResult, 0, len(paths))
	for _, path := range paths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		snapshot, err := tryObjectPullTCPUntil(state, config, peerID, path, deadline)
		if err != nil {
			return fmt.Errorf("recover %s from %s: %w", path, peerID, err)
		}
		result, err := applyRecoveryZoneSnapshot(rt, state, snapshot)
		if err != nil {
			return fmt.Errorf("recover %s from %s: %w", path, peerID, err)
		}
		results = append(results, result)
	}
	if err := rt.SaveState(state); err != nil {
		return err
	}
	for _, result := range results {
		revocations := 0
		if zs := state.Network.Zones[result.Zone]; zs != nil {
			revocations = len(zs.Revocations)
		}
		fmt.Printf("recovered zone %s from %s: records_applied=%d delegations=%d revocations=%d\n",
			result.Zone, peerID, result.Records, result.Delegation, revocations)
	}
	return nil
}

func recoveryChainZones(path zone.ZonePath) []zone.ZonePath {
	ancestors := path.Ancestors()
	out := make([]zone.ZonePath, 0, len(ancestors))
	for i := len(ancestors) - 1; i >= 0; i-- {
		out = append(out, ancestors[i])
	}
	return out
}

func applyRecoveryZoneSnapshot(rt *Runtime, state *stateFile, snapshot *gossip.ZoneSnapshot) (*gossip.ApplyResult, error) {
	if rt == nil {
		return nil, errors.New("runtime is nil")
	}
	if state == nil || state.Network == nil {
		return nil, errors.New("state has no network")
	}
	if snapshot == nil {
		return nil, errors.New("zone snapshot is nil")
	}
	if !snapshot.Zone.Valid() {
		return nil, zone.ErrInvalidZonePath
	}
	if err := validateRecoveryRootSnapshot(rt, state, snapshot); err != nil {
		return nil, err
	}

	config, err := rt.SyncConfig(state)
	if err != nil {
		return nil, err
	}
	limits := syncLimits(config)
	limits.MaxBytes = 8 << 20
	result, err := gossip.ApplySnapshot(state.Network, snapshot, rt.Now(), limits)
	if err != nil {
		return nil, err
	}
	var trustedRoot []byte
	if rt.Config != nil {
		trustedRoot = rt.Config.TrustedRootPublicKey
	}
	if err := verifyConfiguredRootTrustAt(state.Network, trustedRoot); err != nil {
		return nil, err
	}
	return result, nil
}

func validateRecoveryRootSnapshot(rt *Runtime, state *stateFile, snapshot *gossip.ZoneSnapshot) error {
	if snapshot.Zone != zone.RootZone {
		return nil
	}
	if snapshot.Authority == nil {
		return errors.New("root recovery snapshot has no authority")
	}
	if rt.Config != nil && len(rt.Config.TrustedRootPublicKey) > 0 {
		for _, key := range snapshot.Authority.Keys {
			if equalPublicKey(key.Key, rt.Config.TrustedRootPublicKey) {
				return nil
			}
		}
		return errors.New("root recovery snapshot does not match trusted_root_public_key")
	}
	root := state.Network.Zones[zone.RootZone]
	if root == nil || root.Authority == nil {
		return errors.New("root recovery without trusted_root_public_key requires an existing local root authority")
	}
	if !bytes.Equal(higgscrypto.AuthorityHash(root.Authority), higgscrypto.AuthorityHash(snapshot.Authority)) {
		return errors.New("root recovery snapshot changes local root authority without trusted_root_public_key")
	}
	return nil
}

func recoveryPurgeRevoked(apply bool, target zone.ZonePath) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	// Only --apply talks to the daemon so the running node can observe the
	// deletion and reconcile (tear down orphaned IPsec, etc.). A dry-run is a
	// pure local computation and never reaches the daemon.
	if apply {
		plan, controlled, err := purgeRevokedViaControl(rt, apply, target)
		if err != nil {
			return err
		}
		if controlled {
			printPurgePlan(plan, " via daemon")
			return nil
		}
		logControlFallback("recovery_purge_revoked")
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	state.Lock()
	defer state.Unlock()
	plan, err := planPurgeRevokedZones(state, rt.Now(), target)
	if err != nil {
		return err
	}
	if apply {
		executePurgePlan(state, plan)
		if err := rt.SaveState(state); err != nil {
			return err
		}
	}
	printPurgePlan(plan, purgePlanSuffix(apply))
	if !apply {
		fmt.Println("(dry-run; pass --apply to delete)")
	}
	return nil
}

func purgePlanSuffix(apply bool) string {
	if apply {
		return " applied"
	}
	return ""
}

func printPurgePlan(plan *purgePlan, suffix string) {
	if plan == nil {
		fmt.Printf("purge plan%s: unavailable\n", suffix)
		return
	}
	fmt.Printf("purge plan%s: zones=%d link_instances=%d sync_peers=%d\n",
		suffix, len(plan.Zones), len(plan.LinkInstances), len(plan.SyncPeers))
	for _, z := range plan.Zones {
		fmt.Printf("  zone %s\n", z)
	}
	for _, id := range plan.LinkInstances {
		fmt.Printf("  link_instance %s\n", id)
	}
	for _, peerID := range plan.SyncPeers {
		fmt.Printf("  sync_peer %s\n", peerID)
	}
	for _, z := range plan.ManagedZoneSkipped {
		fmt.Printf("  skipped (local identity) %s\n", z)
	}
}
