package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

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
func debugRevokeImpact(ctx context.Context, zoneArg string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}

	// Try daemon live state first.
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
		return writeRevocationImpacts(os.Stdout, impacts)
	}

	// Fallback to local state snapshot.
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	now := rt.Now()
	syncConfig, _ := rt.SyncConfig(state)
	var impacts []RevocationImpact
	if zoneArg != "" {
		impact := ComputeRevocationImpact(state, zone.ZonePath(zoneArg), now)
		impacts = []RevocationImpact{impact}
	} else {
		impacts = AllRevocationImpact(state, syncConfig, now)
	}
	return writeRevocationImpacts(os.Stdout, impacts)
}

func filterImpactsByZone(impacts []RevocationImpact, z zone.ZonePath) []RevocationImpact {
	var out []RevocationImpact
	for _, imp := range impacts {
		if imp.RevokedZone == z {
			out = append(out, imp)
		}
	}
	return out
}

// writeRevocationImpacts writes the revocation impact details to w.
func writeRevocationImpacts(w io.Writer, impacts []RevocationImpact) error {
	if len(impacts) == 0 {
		fmt.Fprintln(w, "no revoked zones")
		return nil
	}
	for _, imp := range impacts {
		writeRevocationImpactDetail(w, imp)
	}
	return nil
}

func writeRevocationImpactDetail(w io.Writer, imp RevocationImpact) {
	fmt.Fprintf(w, "revoked_zone: %s\n", imp.RevokedZone)
	if imp.SourceZone != "" {
		fmt.Fprintf(w, "  source_zone: %s\n", imp.SourceZone)
	}
	if len(imp.RevokedSubtree) > 0 {
		fmt.Fprintf(w, "  affected_subtree:\n")
		for _, z := range imp.RevokedSubtree {
			fmt.Fprintf(w, "    - %s\n", z)
		}
	} else {
		fmt.Fprintf(w, "  affected_subtree: (none)\n")
	}
	if len(imp.AffectedLinkInstances) > 0 {
		fmt.Fprintf(w, "  affected_link_instances:\n")
		for _, id := range imp.AffectedLinkInstances {
			fmt.Fprintf(w, "    - %s\n", id)
		}
	}
	if len(imp.AffectedSyncPeers) > 0 {
		fmt.Fprintf(w, "  affected_sync_peers:\n")
		for _, id := range imp.AffectedSyncPeers {
			fmt.Fprintf(w, "    - %s\n", id)
		}
	}
	if len(imp.ConfiguredButRevoked) > 0 {
		fmt.Fprintf(w, "  configured_but_revoked:\n")
		for _, id := range imp.ConfiguredButRevoked {
			fmt.Fprintf(w, "    - %s\n", id)
		}
		fmt.Fprintln(w, "    note: bootstrap config still points to revoked peer; remove from config or update peer identity")
	}
	if len(imp.AffectedIPAMPrefixes) > 0 {
		fmt.Fprintf(w, "  affected_ipam_prefixes:\n")
		for _, pfx := range imp.AffectedIPAMPrefixes {
			fmt.Fprintf(w, "    - %s\n", pfx)
		}
	}
	if len(imp.Layers) > 0 {
		fmt.Fprintf(w, "  cleanup_layers:\n")
		for _, layer := range orderedLayerNames() {
			status := imp.Layers[layer]
			if status == nil {
				continue
			}
			fmt.Fprintf(w, "    %s:\n", layer)
			fmt.Fprintf(w, "      status: %s\n", status.Status)
			if status.Reason != "" {
				fmt.Fprintf(w, "      reason: %s\n", status.Reason)
			}
			if status.Error != "" {
				fmt.Fprintf(w, "      error: %s\n", status.Error)
			}
			if status.UnixTime != 0 {
				fmt.Fprintf(w, "      time: %s\n", time.Unix(status.UnixTime, 0).Format(time.RFC3339))
			}
		}
	}
	fmt.Fprintln(w)
}

func orderedLayerNames() []string {
	return []string{
		revocationLayerFirewall,
		revocationLayerRouting,
		revocationLayerIPsec,
		revocationLayerGossip,
	}
}
