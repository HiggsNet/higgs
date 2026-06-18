package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

// debugPeers implements `higgs debug peers`: it prints the derived lifecycle
// status of every known peer, including state, reason, last sync, link counts
// and cleanup timers. It prioritizes daemon live state when available.
func debugPeers(ctx context.Context) error {
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
	cfg := PeerLifecycleConfig{}
	if rt != nil && rt.Config != nil {
		cfg = rt.Config.PeerLifecycle
	}
	hasOverlay := rt != nil && rt.Config != nil && len(rt.Config.IPsec.LinkGroups) > 0

	peers := derivePeerStatuses(state, now, cfg, hasOverlay)
	if len(peers) == 0 {
		fmt.Fprintln(w, "no peers known")
		return nil
	}

	fmt.Fprintf(w, "peer lifecycle config: stale_after=%s offline_after=%s cleanup_after=%s keep_sa_while_stale=%v\n",
		formatDuration(normalizedPeerLifecycleConfig(cfg).StaleAfter),
		formatDuration(normalizedPeerLifecycleConfig(cfg).OfflineAfter),
		formatDuration(normalizedPeerLifecycleConfig(cfg).CleanupAfter),
		normalizedPeerLifecycleConfig(cfg).KeepSAWhileStale,
	)
	fmt.Fprintln(w)

	// Summary counts
	counts := make(map[string]int)
	for _, p := range peers {
		counts[p.State]++
	}
	states := make([]string, 0, len(counts))
	for s := range counts {
		states = append(states, s)
	}
	sort.Strings(states)
	fmt.Fprint(w, "summary: ")
	for i, s := range states {
		if i > 0 {
			fmt.Fprint(w, ", ")
		}
		fmt.Fprintf(w, "%s=%d", s, counts[s])
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	for _, p := range peers {
		writePeerStatusDetail(w, p)
	}
	return nil
}

func writePeerStatusDetail(w io.Writer, p PeerStatusInfo) {
	fmt.Fprintf(w, "peer_id: %s\n", p.PeerID)
	fmt.Fprintf(w, "  zone: %s\n", p.Zone)
	fmt.Fprintf(w, "  state: %s\n", p.State)
	if p.Reason != "" {
		fmt.Fprintf(w, "  reason: %s\n", p.Reason)
	}
	if p.Detail != "" {
		fmt.Fprintf(w, "  detail: %s\n", p.Detail)
	}
	fmt.Fprintf(w, "  last_seen: %s\n", formatUnixTime(p.LastSeenUnix))
	fmt.Fprintf(w, "  last_sync: %s\n", formatUnixTime(p.LastSyncUnix))
	fmt.Fprintf(w, "  last_reconcile: %s\n", formatUnixTime(p.LastReconcileUnix))
	fmt.Fprintf(w, "  desired_links: %d\n", p.DesiredLinks)
	fmt.Fprintf(w, "  actual_links: %d\n", p.ActualLinks)
	fmt.Fprintf(w, "  up_links: %d\n", p.UpLinks)
	if p.OfflineSinceUnix != 0 {
		fmt.Fprintf(w, "  offline_since: %s\n", formatUnixTime(p.OfflineSinceUnix))
	}
	if p.NextCleanupUnix != 0 {
		fmt.Fprintf(w, "  next_cleanup: %s\n", formatUnixTime(p.NextCleanupUnix))
	}
	// Severity hint for operators
	switch p.State {
	case peerStateRevoked:
		fmt.Fprintln(w, "  severity: critical (revoked)")
	case peerStateOffline:
		if p.Reason == "cleanup_after_exceeded" {
			fmt.Fprintln(w, "  severity: warning (cleanup due)")
		} else {
			fmt.Fprintln(w, "  severity: warning (offline)")
		}
	case peerStateStale:
		fmt.Fprintln(w, "  severity: info (stale)")
	case peerStatePolicyDenied, peerStateConfigError:
		fmt.Fprintln(w, "  severity: warning (policy/config)")
	default:
		fmt.Fprintln(w, "  severity: ok")
	}
	fmt.Fprintln(w)
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "default"
	}
	return d.String()
}

// peerStatusSnapshotForControl returns the peer status list for a daemon
// control API response. It is called from the control handler when the
// `peers_status` method is invoked.
func (d *DaemonService) peerStatusSnapshotForControl() []PeerStatusInfo {
	if d == nil || d.Sync == nil || d.Sync.State == nil {
		return nil
	}
	d.Sync.State.RLock()
	defer d.Sync.State.RUnlock()
	now := d.Sync.now()
	cfg := PeerLifecycleConfig{}
	if d.Sync.App != nil && d.Sync.App.Config != nil {
		cfg = d.Sync.App.Config.PeerLifecycle
	}
	hasOverlay := d.Sync.App != nil && d.Sync.App.Config != nil && len(d.Sync.App.Config.IPsec.LinkGroups) > 0
	return derivePeerStatuses(d.Sync.State, now, cfg, hasOverlay)
}

// peerLifecycleCleanupZones returns peer zones that should have their Higgs
// owner-managed SA/interface/route/firewall objects cleaned up. This is the
// 6.4.2 cleanup_after / 6.4.5 revoked entry point: it is called by the
// daemon's periodic timer to discover long-term offline or revoked peers that
// need resource cleanup beyond normal reconcile teardown.
func peerLifecycleCleanupZones(state *stateFile, now time.Time, cfg PeerLifecycleConfig) []zone.ZonePath {
	if state == nil {
		return nil
	}
	cfg = normalizedPeerLifecycleConfig(cfg)
	hasOverlay := hasIPsecConfig(state)
	peers := derivePeerStatuses(state, now, cfg, hasOverlay)
	var out []zone.ZonePath
	seen := make(map[zone.ZonePath]bool)
	for _, p := range peers {
		if peerStatusRequiresCleanup(p, cfg) && !seen[p.Zone] {
			seen[p.Zone] = true
			out = append(out, p.Zone)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i] < out[j]
	})
	return out
}
