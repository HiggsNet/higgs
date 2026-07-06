package text

import (
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
)

func TestWritePeerLifecycleDebugNoPeers(t *testing.T) {
	var buf strings.Builder
	if err := WritePeerLifecycleDebug(&buf, PeerLifecycleDebugView{}); err != nil {
		t.Fatalf("WritePeerLifecycleDebug: %v", err)
	}
	if got := buf.String(); got != "no peers known\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestWritePeerLifecycleDebugSummaryAndSeverity(t *testing.T) {
	view := PeerLifecycleDebugView{
		Config: PeerLifecycleDebugConfig{
			StaleAfter:       15 * time.Minute,
			OfflineAfter:     12 * time.Hour,
			CleanupAfter:     48 * time.Hour,
			KeepSAWhileStale: true,
		},
		Peers: []inspect.PeerStatusInfo{
			{
				PeerID:            "node-b.catofes.",
				Zone:              "node-b.catofes.",
				State:             "revoked",
				Reason:            "zone_revoked",
				Detail:            "revoked by catofes.",
				LastSeenUnix:      1700000000,
				LastSyncUnix:      1700000001,
				LastReconcileUnix: 1700000002,
				DesiredLinks:      1,
				ActualLinks:       1,
				UpLinks:           0,
			},
			{
				PeerID:           "node-c.catofes.",
				Zone:             "node-c.catofes.",
				State:            "offline",
				Reason:           "cleanup_after_exceeded",
				OfflineSinceUnix: 1700000010,
				NextCleanupUnix:  1700000020,
			},
		},
	}

	var buf strings.Builder
	if err := WritePeerLifecycleDebug(&buf, view); err != nil {
		t.Fatalf("WritePeerLifecycleDebug: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"peer lifecycle config: stale_after=15m0s offline_after=12h0m0s cleanup_after=48h0m0s keep_sa_while_stale=true",
		"summary: offline=1, revoked=1",
		"peer_id: node-b.catofes.",
		"  zone: node-b.catofes.",
		"  state: revoked",
		"  reason: zone_revoked",
		"  detail: revoked by catofes.",
		"  last_seen: 2023-11-14T22:13:20Z",
		"  last_sync: 2023-11-14T22:13:21Z",
		"  last_reconcile: 2023-11-14T22:13:22Z",
		"  desired_links: 1",
		"  actual_links: 1",
		"  up_links: 0",
		"  severity: critical (revoked)",
		"peer_id: node-c.catofes.",
		"  offline_since: 2023-11-14T22:13:30Z",
		"  next_cleanup: 2023-11-14T22:13:40Z",
		"  severity: warning (cleanup due)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}
