package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
	"github.com/Catofes/higgs/pkg/core/zone"
)

// debugPeers implements `higgs debug peers`: it prints the derived lifecycle
// status of every known peer, including state, reason, last sync, link counts
// and cleanup timers. It prioritizes daemon live state when available.
func debugPeers(_ context.Context) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := daemonStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online peer_id=%s link_instances=%d desired_links=%d\n",
			response.PeerID,
			response.LinkInstances,
			response.DesiredLinks,
		)
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	return writeDebugPeers(os.Stdout, rt, state)
}

// writeDebugPeers writes the peer status table to w. It is separated from
// debugPeers for testability.
func writeDebugPeers(w io.Writer, rt *Runtime, state *stateFile) error {
	if state == nil {
		return nil
	}
	now := rt.Now()
	cfg := inspect.PeerLifecycleConfig{}
	if rt != nil && rt.Config != nil {
		cfg = rt.Config.PeerLifecycle
	}
	hasOverlay := rt != nil && rt.Config != nil && len(rt.Config.IPsec.LinkGroups) > 0

	peers := derivePeerStatuses(state, now, cfg, hasOverlay)
	normalized := inspect.NormalizePeerLifecycleConfig(cfg)
	return inspecttext.WritePeerLifecycleDebug(w, inspecttext.PeerLifecycleDebugView{
		Config: inspecttext.PeerLifecycleDebugConfig{
			StaleAfter:       normalized.StaleAfter,
			OfflineAfter:     normalized.OfflineAfter,
			CleanupAfter:     normalized.CleanupAfter,
			KeepSAWhileStale: normalized.KeepSAWhileStale,
		},
		Peers: peers,
	})
}

// peerStatusSnapshotForControl returns the peer status list for a daemon
// control API response. It is called from the control handler when the
// `peers_status` method is invoked.
func (d *DaemonService) peerStatusSnapshotForControl() ([]inspect.PeerStatusInfo, daemonStateStoreMeta) {
	if d == nil || d.Sync == nil {
		return nil, daemonStateStoreMeta{}
	}
	state, _, meta := d.snapshotState()
	if state == nil {
		return nil, meta
	}
	now := d.Sync.now()
	cfg := inspect.PeerLifecycleConfig{}
	if d.Sync.App != nil && d.Sync.App.Config != nil {
		cfg = d.Sync.App.Config.PeerLifecycle
	}
	hasOverlay := d.Sync.App != nil && d.Sync.App.Config != nil && len(d.Sync.App.Config.IPsec.LinkGroups) > 0
	return derivePeerStatuses(state, now, cfg, hasOverlay), meta
}

// peerLifecycleCleanupZones returns peer zones that should have their Higgs
// owner-managed SA/interface/route/firewall objects cleaned up. This is the
// 6.4.2 cleanup_after / 6.4.5 revoked entry point: it is called by the
// daemon's periodic timer to discover long-term offline or revoked peers that
// need resource cleanup beyond normal reconcile teardown.
func peerLifecycleCleanupZones(state *stateFile, now time.Time, cfg inspect.PeerLifecycleConfig) []zone.ZonePath {
	if state == nil {
		return nil
	}
	cfg = inspect.NormalizePeerLifecycleConfig(cfg)
	hasOverlay := hasIPsecConfig(state)
	peers := derivePeerStatuses(state, now, cfg, hasOverlay)
	var out []zone.ZonePath
	seen := make(map[zone.ZonePath]bool)
	for _, p := range peers {
		if inspect.PeerStatusRequiresCleanup(p) && !seen[p.Zone] {
			seen[p.Zone] = true
			out = append(out, p.Zone)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i] < out[j]
	})
	return out
}
