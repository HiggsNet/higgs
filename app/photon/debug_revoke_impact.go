package main

import (
	"context"
	"fmt"
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// revokeStatusViaControl queries the daemon for the live revocation impact
// snapshot. It returns (response, daemonOnline, error).
func revokeStatusViaControl(rt *Runtime) (*controlResponse, bool, error) {
	if rt == nil || rt.DisableControl {
		return nil, false, nil
	}
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "revoke_status"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, false, nil
	}
	return response, true, err
}

// debugRevokeImpact implements `photon debug revoke-impact [zone]`: it shows
// the revocation impact (affected subtree, link instances, sync peers,
// configured-but-revoked peers, IPAM prefixes and per-layer cleanup status)
// for all currently-revoked zones, or for a single zone if specified.
func debugRevokeImpact(_ context.Context, zoneArg string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}

	// Try daemon committed state first.
	if response, ok, err := revokeStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		if response.PeerID != "" {
			fmt.Printf("daemon: online peer_id=%s\n", response.PeerID)
		}
		impacts := response.RevocationImpact
		if zoneArg != "" {
			impacts = filterImpactsByZone(impacts, zone.ZonePath(zoneArg))
		}
		return inspecttext.WriteRevocationImpacts(os.Stdout, impacts)
	}

	// Fallback to local state snapshot.
	common, runtime, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil || runtime == nil {
		return fmt.Errorf("state owners are not initialized")
	}
	now := rt.Now()
	peers := syncPeerReadView(common.Gossip)
	syncConfig := syncConfigFromAppConfig(rt.Config, common.State)
	var impacts []inspect.RevocationImpact
	if zoneArg != "" {
		impact := ComputeRevocationImpact(common.State.Network, runtime.LinkInstances, peers, zone.ZonePath(zoneArg), now)
		impacts = []inspect.RevocationImpact{impact}
	} else {
		impacts = AllRevocationImpact(common.State.Network, runtime.LinkInstances, peers, syncConfig, now)
	}
	return inspecttext.WriteRevocationImpacts(os.Stdout, impacts)
}

func filterImpactsByZone(impacts []inspect.RevocationImpact, z zone.ZonePath) []inspect.RevocationImpact {
	var out []inspect.RevocationImpact
	for _, imp := range impacts {
		if imp.RevokedZone == z {
			out = append(out, imp)
		}
	}
	return out
}
