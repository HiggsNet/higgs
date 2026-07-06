package text

import (
	"io"
	"sort"

	"github.com/Catofes/higgs/internal/inspect"
)

func WritePeerLifecycleDebug(w io.Writer, view inspect.PeerLifecycleDebugView) error {
	out := newLineWriter(w)
	if len(view.Peers) == 0 {
		out.Println("no peers known")
		return out.Err()
	}
	out.Linef("peer lifecycle config: stale_after=%s offline_after=%s cleanup_after=%s keep_sa_while_stale=%v",
		formatDuration(view.Config.StaleAfter),
		formatDuration(view.Config.OfflineAfter),
		formatDuration(view.Config.CleanupAfter),
		view.Config.KeepSAWhileStale,
	)
	out.Blank()

	counts := make(map[string]int)
	for _, p := range view.Peers {
		counts[p.State]++
	}
	states := make([]string, 0, len(counts))
	for state := range counts {
		states = append(states, state)
	}
	sort.Strings(states)
	out.Printf("summary: ")
	for i, state := range states {
		if i > 0 {
			out.Printf(", ")
		}
		out.Printf("%s=%d", state, counts[state])
	}
	out.Blank()
	out.Blank()
	if err := out.Err(); err != nil {
		return err
	}

	for _, peer := range view.Peers {
		if err := WritePeerStatusDetail(w, peer); err != nil {
			return err
		}
	}
	return nil
}

func WritePeerStatusDetail(w io.Writer, p inspect.PeerStatusInfo) error {
	out := newLineWriter(w)
	out.Linef("peer_id: %s", p.PeerID)
	out.Linef("  zone: %s", p.Zone)
	out.Linef("  state: %s", p.State)
	out.LineIf(p.Reason != "", "  reason: %s", p.Reason)
	out.LineIf(p.Detail != "", "  detail: %s", p.Detail)
	out.Linef("  last_seen: %s", formatUnixTime(p.LastSeenUnix))
	out.Linef("  last_sync: %s", formatUnixTime(p.LastSyncUnix))
	out.Linef("  last_reconcile: %s", formatUnixTime(p.LastReconcileUnix))
	out.Linef("  desired_links: %d", p.DesiredLinks)
	out.Linef("  actual_links: %d", p.ActualLinks)
	out.Linef("  up_links: %d", p.UpLinks)
	out.LineIf(p.OfflineSinceUnix != 0, "  offline_since: %s", formatUnixTime(p.OfflineSinceUnix))
	out.LineIf(p.NextCleanupUnix != 0, "  next_cleanup: %s", formatUnixTime(p.NextCleanupUnix))
	out.Linef("  severity: %s", peerSeverity(p))
	out.Blank()
	return out.Err()
}

func peerSeverity(p inspect.PeerStatusInfo) string {
	switch p.State {
	case "revoked":
		return "critical (revoked)"
	case "offline":
		if p.Reason == "cleanup_after_exceeded" {
			return "warning (cleanup due)"
		}
		return "warning (offline)"
	case "stale":
		return "info (stale)"
	case "policy_denied", "config_error":
		return "warning (policy/config)"
	default:
		return "ok"
	}
}
