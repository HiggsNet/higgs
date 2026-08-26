package main

import (
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/internal/observability"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestBuildDebugPeerViewRejectsUnknownZone(t *testing.T) {
	now := time.Unix(1700000000, 0)
	state := &stateFile{
		Network:   zone.NewNetworkState(),
		SyncPeers: map[string]syncPeerState{"node-b.catofes.": {}},
	}
	config := &syncConfigFile{PeerID: "node-a.catofes."}

	_, err := buildDebugPeerView(state, config, "ss", now)
	if !errors.Is(err, zone.ErrZoneNotFound) {
		t.Fatalf("buildDebugPeerView error = %v, want ErrZoneNotFound", err)
	}
	if got, want := err.Error(), "zone not found: ss"; got != want {
		t.Fatalf("buildDebugPeerView error = %q, want %q", got, want)
	}
}

func TestSyncStatusAdapterDoesNotProjectEphemeralDiagnosticsFromState(t *testing.T) {
	now := time.Unix(1700000000, 0)
	state := &stateFile{
		Network: &zone.NetworkState{Zones: map[zone.ZonePath]*zone.ZoneState{}},
		SyncPeers: map[string]syncPeerState{
			"node-b.catofes.": diagnosticSyncPeerState(now),
		},
	}
	config := &syncConfigFile{
		PeerID:          "node-a.catofes.",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: 4096,
		MaxSyncZones:    8,
		MaxSyncRecords:  64,
		Bootstrap: []syncConfigPeer{{
			ID:   "node-b.catofes.",
			Addr: "127.0.0.1:9999",
		}},
	}
	view := buildSyncStatusView(state, config, now, true)

	if len(view.Bootstrap) != 1 {
		t.Fatalf("bootstrap peers = %+v, want one", view.Bootstrap)
	}
	peer := view.Bootstrap[0]
	if peer.PeerID != "node-b.catofes." || peer.ConfiguredAddr != "127.0.0.1:9999" {
		t.Fatalf("bootstrap peer = %+v", peer)
	}
	if peer.SyncFlow.ActivePullState != "" || peer.SyncFlow.HintAccepted != 0 || peer.SyncFlow.HintSuppressed != 0 || peer.SyncFlow.ReadOnlyResponder != 0 {
		t.Fatalf("offline status retained ephemeral sync diagnostics: %+v", peer.SyncFlow)
	}
	if peer.DatagramStats != (inspect.PeerDatagramStatsView{}) || peer.ObjectPullStats != (inspect.PeerObjectPullStatsView{}) {
		t.Fatalf("offline status retained ephemeral diagnostics: datagram=%+v object-pull=%+v", peer.DatagramStats, peer.ObjectPullStats)
	}
}

func TestSyncStatusGroupsZonesByDotAndHyphenSuffix(t *testing.T) {
	network := zone.NewNetworkState()
	for _, path := range []zone.ZonePath{
		"a-sha.catofes.",
		"b-pek.catofes.",
		"a-pek.catofes.",
		"alpha.catofes.",
	} {
		network.Zones[path] = zone.NewZoneState(path, nil)
	}
	view := buildSyncStatusView(
		&stateFile{Network: network, SyncPeers: map[string]syncPeerState{}},
		&syncConfigFile{},
		time.Unix(1700000000, 0),
		false,
	)
	want := []string{
		"alpha.catofes.",
		"a-pek.catofes.",
		"b-pek.catofes.",
		"a-sha.catofes.",
	}
	if len(view.Zones) != len(want) {
		t.Fatalf("zones = %+v, want %d", view.Zones, len(want))
	}
	for i, path := range want {
		if view.Zones[i].Zone != string(path) {
			t.Fatalf("zones[%d] = %q, want %q; all=%+v", i, view.Zones[i].Zone, path, view.Zones)
		}
	}
}

func TestPeerDebugAdapterProjectsRuntimeStats(t *testing.T) {
	now := time.Unix(1700000000, 0)
	view := buildPeerDebugView(
		"node-b.catofes.",
		"bootstrap",
		"127.0.0.1:9999",
		"127.0.0.1:2000",
		diagnosticSyncPeerState(now),
		diagnosticPeerObservability(now),
		now,
	)

	if view.PeerID != "node-b.catofes." || view.Source != "bootstrap" || view.ConfiguredAddr != "127.0.0.1:9999" || view.ResolvedAddr != "127.0.0.1:2000" {
		t.Fatalf("peer debug identity = %+v", view)
	}
	if view.DiscoveredAddr != "127.0.0.1:2000" || view.ObservedAddr != "127.0.0.1:3000" || view.LastUpdateSource != "node-c.catofes." {
		t.Fatalf("peer endpoint fields = %+v", view)
	}
	if view.SyncFlow.ActivePullState != string(gossip.SyncSessionObjectPulling) || view.SyncFlow.ActivePullLastEvent != "catalog_page" {
		t.Fatalf("sync flow = %+v", view.SyncFlow)
	}
	if view.DatagramStats.TooLargeDropped != 2 || view.DatagramStats.LastTooLargeObject != "record" {
		t.Fatalf("datagram stats = %+v", view.DatagramStats)
	}
	if view.ObjectPullStats.Attempts != 3 || !view.ObjectPullStats.LastUnreachable || view.ObjectPullStats.LastError != "no TCP address" {
		t.Fatalf("object pull stats = %+v", view.ObjectPullStats)
	}
}

func diagnosticSyncPeerState(now time.Time) syncPeerState {
	return syncPeerState{
		LastSyncUnix:          now.Unix(),
		DiscoveredAddr:        "127.0.0.1:2000",
		DiscoveredAtUnix:      now.Unix(),
		ObservedAddr:          "127.0.0.1:3000",
		ObservedFirstSeenUnix: now.Unix(),
		ObservedLastSeenUnix:  now.Unix(),
		ObservedLastSyncUnix:  now.Unix(),
		ObservedUntilUnix:     now.Add(time.Hour).Unix(),
		ObservedSource:        string(gossip.MessagePing),
		LastUpdateSource:      "node-c.catofes.",
	}
}

func diagnosticPeerObservability(now time.Time) observability.PeerSnapshot {
	return observability.PeerSnapshot{
		ActivePullState:       string(gossip.SyncSessionObjectPulling),
		ActivePullLastEvent:   "catalog_page",
		ActivePullUpdatedUnix: now.Unix(),
		HintAccepted:          2,
		HintSuppressed:        1,
		LastHintUnix:          now.Unix(),
		LastHintReason:        "announce_hint",
		LastHintSuppression:   "session_active",
		ReadOnlyResponder:     3,
		LastResponderUnix:     now.Unix(),
		LastResponderKind:     "chunk_fallback",
		LastResponderZone:     "node-b.catofes.",
		DatagramStats:         diagnosticDatagramStats(now),
		ObjectPullStats:       diagnosticObjectPullStats(now),
	}
}

func diagnosticDatagramStats(now time.Time) *datagramStats {
	return &datagramStats{
		TooLargeDropped:       2,
		DigestOnlyAnnounces:   1,
		LastTooLargeUnix:      now.Unix(),
		LastTooLargeDirection: "send",
		LastTooLargeObject:    "record",
		LastTooLargeZone:      "node-b.catofes.",
		LastTooLargeKey:       "bigdata",
		LastTooLargeBytes:     1800,
		LastTooLargeLimit:     gossip.DefaultDatagramBudget,
	}
}

func diagnosticObjectPullStats(now time.Time) *objectPullStats {
	return &objectPullStats{
		Attempts:               3,
		Successes:              2,
		Failures:               1,
		LargeObjectUnreachable: 1,
		LastUnix:               now.Unix(),
		LastError:              "no TCP address",
		LastObject:             "record",
		LastZone:               "node-b.catofes.",
		LastKey:                "bigdata",
		LastBytes:              4096,
		LastSourcePeer:         "node-b.catofes.",
		LastUnreachable:        true,
	}
}
