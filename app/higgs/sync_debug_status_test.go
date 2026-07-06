package main

import (
	"testing"
	"time"
)

func TestBuildSyncStatusViewProjectsVerboseDiagnostics(t *testing.T) {
	prepareDiagnosticsState(t)

	rt, err := NewRuntime()
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	config, err := rt.SyncConfig(state)
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	view := buildSyncStatusView(state, config, time.Unix(1700000000, 0), true)

	if view.PeerID != "node-a.catofes." || view.ListenAddr != "127.0.0.1:0" || view.KnownPeers != 1 || view.KnownZones != 3 {
		t.Fatalf("sync status summary = %+v", view)
	}
	if view.Limits.MaxDatagramBytes != 4096 || view.Limits.MaxSyncZones != 8 || view.Limits.MaxSyncRecords != 64 || view.Limits.WireCodec != "msgpack" {
		t.Fatalf("sync limits = %+v", view.Limits)
	}
	if !view.Verbose || view.AllowlistSource != "bootstrap+discovery" || view.BootstrapPeers != 1 {
		t.Fatalf("verbose metadata = %+v", view)
	}
	if len(view.Bootstrap) != 1 {
		t.Fatalf("bootstrap peers = %+v, want one", view.Bootstrap)
	}
	peer := view.Bootstrap[0]
	if peer.PeerID != "node-b.catofes." || peer.ConfiguredAddr != "127.0.0.1:9999" || peer.ResolvedAddr != "127.0.0.1:9999" {
		t.Fatalf("bootstrap peer = %+v", peer)
	}
	if peer.SyncFlow.ActivePullState != string(SyncSessionObjectPulling) || peer.SyncFlow.ReadOnlyResponder != 3 {
		t.Fatalf("sync flow = %+v", peer.SyncFlow)
	}
	if peer.DatagramStats.TooLargeDropped != 2 || peer.DatagramStats.DigestOnlyAnnounces != 1 {
		t.Fatalf("datagram stats = %+v", peer.DatagramStats)
	}
	if peer.ObjectPullStats.Attempts != 3 || peer.ObjectPullStats.LargeObjectUnreachable != 1 {
		t.Fatalf("object pull stats = %+v", peer.ObjectPullStats)
	}
	if len(view.Zones) == 0 {
		t.Fatalf("zones = %+v, want zone summaries", view.Zones)
	}
}

func TestBuildPeerDebugViewProjectsRuntimeStats(t *testing.T) {
	prepareDiagnosticsState(t)

	rt, err := NewRuntime()
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	peerState := state.SyncPeers["node-b.catofes."]
	view := buildPeerDebugView("node-b.catofes.", "bootstrap", "127.0.0.1:9999", "127.0.0.1:2000", peerState, time.Unix(1700000000, 0))

	if view.PeerID != "node-b.catofes." || view.Source != "bootstrap" || view.ConfiguredAddr != "127.0.0.1:9999" || view.ResolvedAddr != "127.0.0.1:2000" {
		t.Fatalf("peer debug identity = %+v", view)
	}
	if view.DiscoveredAddr != "127.0.0.1:2000" || view.ObservedAddr != "127.0.0.1:3000" || view.LastUpdateSource != "node-c.catofes." {
		t.Fatalf("peer endpoint fields = %+v", view)
	}
	if view.SyncFlow.ActivePullState != string(SyncSessionObjectPulling) || view.SyncFlow.ActivePullLastEvent != "catalog_page" {
		t.Fatalf("sync flow = %+v", view.SyncFlow)
	}
	if view.DatagramStats.TooLargeDropped != 2 || view.DatagramStats.LastTooLargeObject != "record" {
		t.Fatalf("datagram stats = %+v", view.DatagramStats)
	}
	if view.ObjectPullStats.Attempts != 3 || !view.ObjectPullStats.LastUnreachable || view.ObjectPullStats.LastError != "no TCP address" {
		t.Fatalf("object pull stats = %+v", view.ObjectPullStats)
	}
}
