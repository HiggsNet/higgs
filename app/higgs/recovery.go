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
		},
	}
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
