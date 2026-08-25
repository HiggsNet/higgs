package main

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestShouldRelayToPeer(t *testing.T) {
	now := time.Unix(100, 0)
	tests := []struct {
		name    string
		state   syncPeerState
		peerID  string
		source  string
		root    string
		allowed bool
		reason  string
	}{
		{
			name:   "empty peer",
			peerID: "",
			source: "node-a",
			reason: "empty_peer_id",
		},
		{
			name:   "source peer",
			peerID: "node-a",
			source: "node-a",
			reason: "source_peer",
		},
		{
			name:   "backoff",
			state:  syncPeerState{BackoffUntilUnix: now.Add(time.Second).Unix()},
			peerID: "node-b",
			source: "node-a",
			reason: "backoff",
		},
		{
			name:   "same catalog root",
			state:  syncPeerState{LastRelayCatalogRootHex: "root-a"},
			peerID: "node-b",
			source: "node-a",
			root:   "root-a",
			reason: "relay_root_unchanged",
		},
		{
			name:   "throttled",
			state:  syncPeerState{LastRelayUnix: now.Unix()},
			peerID: "node-b",
			source: "node-a",
			reason: "relay_throttled",
		},
		{
			name:    "allowed",
			state:   syncPeerState{LastRelayUnix: now.Add(-relayMinInterval).Unix()},
			peerID:  "node-b",
			source:  "node-a",
			allowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := shouldRelayToPeer(tt.state, tt.peerID, tt.source, tt.root, now)
			if allowed != tt.allowed || reason != tt.reason {
				t.Fatalf("shouldRelayToPeer() = %v, %q; want %v, %q", allowed, reason, tt.allowed, tt.reason)
			}
		})
	}
}

func TestRecordRelaySuppression(t *testing.T) {
	state := &stateFile{}
	now := time.Unix(100, 0)

	recordRelaySuppression(state, "node-b", "relay_throttled", now)

	peerState := state.SyncPeers["node-b"]
	if peerState.LastRelaySuppression != "relay_throttled" {
		t.Fatalf("LastRelaySuppression = %q, want relay_throttled", peerState.LastRelaySuppression)
	}
	if peerState.LastRelaySuppressedAt != now.Unix() {
		t.Fatalf("LastRelaySuppressedAt = %d, want %d", peerState.LastRelaySuppressedAt, now.Unix())
	}
}

func TestRecordRelaySuccess(t *testing.T) {
	state := &stateFile{
		SyncPeers: map[string]syncPeerState{
			"node-b": {LastRelaySuppression: "relay_throttled", LastRelaySuppressedAt: 99},
		},
	}
	now := time.Unix(100, 0)

	recordRelaySuccess(state, "node-b", "node-a", "catalog-root-a", now)

	peerState := state.SyncPeers["node-b"]
	if peerState.LastRelayUnix != now.Unix() {
		t.Fatalf("LastRelayUnix = %d, want %d", peerState.LastRelayUnix, now.Unix())
	}
	if peerState.LastUpdateSource != "node-a" {
		t.Fatalf("LastUpdateSource = %q, want node-a", peerState.LastUpdateSource)
	}
	if peerState.LastRelayCatalogRootHex != "catalog-root-a" {
		t.Fatalf("LastRelayCatalogRootHex = %q, want catalog-root-a", peerState.LastRelayCatalogRootHex)
	}
	if peerState.LastRelaySuppression != "" || peerState.LastRelaySuppressedAt != 0 {
		t.Fatalf("relay suppression was not cleared: %#v", peerState)
	}
}

func TestRecordPeerSyncBackoffAndRecovery(t *testing.T) {
	state := &stateFile{}

	recordPeerSync(state, "node-b", errors.New("dial failed"))
	failed := state.SyncPeers["node-b"]
	if failed.FailureCount != 1 {
		t.Fatalf("FailureCount after failure = %d, want 1", failed.FailureCount)
	}
	if failed.LastError != "dial failed" {
		t.Fatalf("LastError = %q, want dial failed", failed.LastError)
	}
	if failed.BackoffUntilUnix == 0 {
		t.Fatalf("BackoffUntilUnix was not set")
	}

	recordPeerSync(state, "node-b", nil)
	recovered := state.SyncPeers["node-b"]
	if recovered.FailureCount != 0 || recovered.LastError != "" || recovered.BackoffUntilUnix != 0 {
		t.Fatalf("peer did not recover cleanly: %#v", recovered)
	}
	if recovered.LastSyncUnix == 0 {
		t.Fatalf("LastSyncUnix was not set on recovery")
	}

	lastSuccess := recovered.LastSyncUnix
	recordPeerSync(state, "node-b", errors.New("sync receive timed out"))
	failedAgain := state.SyncPeers["node-b"]
	if failedAgain.LastSyncUnix != lastSuccess {
		t.Fatalf("LastSyncUnix after later failure = %d, want previous %d", failedAgain.LastSyncUnix, lastSuccess)
	}
	if got := formatLastSuccess(failedAgain); got == "never" {
		t.Fatalf("formatLastSuccess after later failure = %q, want previous success timestamp", got)
	}
}

func TestRelayRejectsSourceAndBackoffToLimitStorm(t *testing.T) {
	now := time.Unix(1000, 0)
	state := &stateFile{SyncPeers: map[string]syncPeerState{
		"node-b.catofes.": {},
		"node-c.catofes.": {BackoffUntilUnix: now.Add(time.Minute).Unix()},
	}}

	if allowed, reason := shouldRelayToPeer(state.SyncPeers["node-b.catofes."], "node-b.catofes.", "node-b.catofes.", "root-a", now); allowed || reason != "source_peer" {
		t.Fatalf("source relay decision = %v %q, want source_peer suppression", allowed, reason)
	}
	if allowed, reason := shouldRelayToPeer(state.SyncPeers["node-c.catofes."], "node-c.catofes.", "node-b.catofes.", "root-a", now); allowed || reason != "backoff" {
		t.Fatalf("backoff relay decision = %v %q, want backoff suppression", allowed, reason)
	}
}

func TestRelaySyncQueuesCompactCatalogSummary(t *testing.T) {
	state, config := buildTestNetworkState(t)
	config.Bootstrap = []syncConfigPeer{{ID: "node-c.catofes.", Addr: "127.0.0.1:33434"}}
	now := time.Unix(1000, 0)
	service := newDaemonService(&Runtime{Clock: func() time.Time { return now }}, state, config, defaultDaemonInterval)

	service.relaySyncToPeers("node-b.catofes.")

	select {
	case event := <-service.syncEvents:
		timer, ok := event.(*SyncTimerEvent)
		if !ok {
			t.Fatalf("relay event = %T, want *SyncTimerEvent", event)
		}
		if timer.LocalSummary == nil {
			t.Fatal("relay event omitted local catalog summary")
		}
		wantRoot := gossip.CatalogRoot(timer.LocalDigests)
		if !bytes.Equal(timer.LocalSummary.CatalogRoot, wantRoot) {
			t.Fatalf("relay summary root = %x, want %x", timer.LocalSummary.CatalogRoot, wantRoot)
		}
		if timer.LocalSummary.ZoneCount != len(timer.LocalDigests) {
			t.Fatalf("relay summary zone count = %d, want %d", timer.LocalSummary.ZoneCount, len(timer.LocalDigests))
		}
		pingSize, err := gossip.WireEncodeSize(&gossip.Message{
			Type: gossip.MessagePing,
			Ping: &gossip.Ping{Summary: timer.LocalSummary},
		})
		if err != nil {
			t.Fatalf("encode relay ping: %v", err)
		}
		if pingSize > service.syncDatagramBudget() {
			t.Fatalf("relay ping size = %d, budget = %d", pingSize, service.syncDatagramBudget())
		}
	default:
		t.Fatal("relay did not queue a sync event")
	}
}
