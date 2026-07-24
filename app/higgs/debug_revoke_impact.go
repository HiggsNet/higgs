package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
	"github.com/Catofes/higgs/pkg/core/zone"
)

// revokeStatusViaControl queries the daemon for the live revocation impact
// snapshot. It returns (response, daemonOnline, error).
func revokeStatusViaControl(rt *Runtime) (*controlResponse, bool, error) {
	path := controlSocketPath(rt.Config)
	response, err := sendControlRequest(path, controlRequest{Method: "revoke_status"})
	if err != nil && isControlSocketUnavailable(err) {
		return nil, false, nil
	}
	return response, true, err
}

// debugRevokeImpact implements `higgs debug revoke-impact [zone]`: it shows
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
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	now := rt.Now()
	syncConfig, _ := rt.SyncConfig(state)
	var impacts []inspect.RevocationImpact
	if zoneArg != "" {
		impact := ComputeRevocationImpact(state, zone.ZonePath(zoneArg), now)
		impacts = []inspect.RevocationImpact{impact}
	} else {
		impacts = AllRevocationImpact(state, syncConfig, now)
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
