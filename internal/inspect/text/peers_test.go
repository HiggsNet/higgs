package text

import (
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestWritePeersUsesConnectionSummaryAndVerboseTables(t *testing.T) {
	view := inspect.PeerLifecycleDebugView{Peers: []inspect.PeerStatusInfo{
		{
			PeerID: "node-a.catofes.", Zone: zone.ZonePath("node-a.catofes."),
			State: "active", UpLinks: 1, ActualLinks: 1, DesiredLinks: 2,
			LastSeenUnix: time.Unix(1700000000, 0).Unix(),
		},
		{
			PeerID: "node-b.catofes.", Zone: zone.ZonePath("node-b.catofes."),
			State: "offline", Reason: "sync_timeout", Detail: "last attempt failed",
		},
	}}
	var summary strings.Builder
	if err := WritePeers(&summary, view, "", false); err != nil {
		t.Fatalf("WritePeers summary: %v", err)
	}
	for _, want := range []string{"PEER", "STATE", "LINKS", "LAST_SEEN", "node-a.catofes.", "1/1/2", "node-b.catofes.", "offline"} {
		if !strings.Contains(summary.String(), want) {
			t.Fatalf("summary missing %q:\n%s", want, summary.String())
		}
	}
	var verbose strings.Builder
	if err := WritePeers(&verbose, view, "node-b", true); err != nil {
		t.Fatalf("WritePeers verbose: %v", err)
	}
	for _, want := range []string{"peers: 1/2", "LAST_SYNC", "NEXT_CLEANUP", "DETAIL", "sync_timeout", "last attempt failed"} {
		if !strings.Contains(verbose.String(), want) {
			t.Fatalf("verbose output missing %q:\n%s", want, verbose.String())
		}
	}
	if strings.Contains(verbose.String(), "node-a.catofes.") {
		t.Fatalf("filter leaked node-a:\n%s", verbose.String())
	}
}

func TestWritePeerLifecycleDebugNoPeers(t *testing.T) {
	var buf strings.Builder
	if err := WritePeerLifecycleDebug(&buf, inspect.PeerLifecycleDebugView{}); err != nil {
		t.Fatalf("WritePeerLifecycleDebug: %v", err)
	}
	if got := buf.String(); got != "no peers known\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestWritePeerLifecycleDebugSummaryAndSeverity(t *testing.T) {
	view := inspect.PeerLifecycleDebugView{
		Config: inspect.PeerLifecycleDebugConfig{
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
