package main

import (
	"testing"
	"time"
)

func TestShouldRelayToPeer(t *testing.T) {
	now := time.Unix(100, 0)
	tests := []struct {
		name    string
		state   syncPeerState
		peerID  string
		source  string
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
			allowed, reason := shouldRelayToPeer(tt.state, tt.peerID, tt.source, now)
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

	recordRelaySuccess(state, "node-b", "node-a", now)

	peerState := state.SyncPeers["node-b"]
	if peerState.LastRelayUnix != now.Unix() {
		t.Fatalf("LastRelayUnix = %d, want %d", peerState.LastRelayUnix, now.Unix())
	}
	if peerState.LastUpdateSource != "node-a" {
		t.Fatalf("LastUpdateSource = %q, want node-a", peerState.LastUpdateSource)
	}
	if peerState.LastRelaySuppression != "" || peerState.LastRelaySuppressedAt != 0 {
		t.Fatalf("relay suppression was not cleared: %#v", peerState)
	}
}
