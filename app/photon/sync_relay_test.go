package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestRecordRelaySuppression(t *testing.T) {
	store := observability.NewPeerObservabilityStore(8, time.Hour)
	now := time.Unix(100, 0)

	recordRelaySuppression(store, "node-b", "relay_throttled", now)

	diagnostics, ok := store.Snapshot("node-b", now)
	if !ok || diagnostics.LastRelaySuppression != "relay_throttled" {
		t.Fatalf("LastRelaySuppression = %q, want relay_throttled", diagnostics.LastRelaySuppression)
	}
	if diagnostics.LastRelaySuppressedAt != now.Unix() {
		t.Fatalf("LastRelaySuppressedAt = %d, want %d", diagnostics.LastRelaySuppressedAt, now.Unix())
	}
}

func TestRecordRelaySuccessDiagnostics(t *testing.T) {
	store := observability.NewPeerObservabilityStore(8, time.Hour)
	now := time.Unix(100, 0)
	recordRelaySuppression(store, "node-b", "relay_throttled", now.Add(-time.Second))

	recordRelaySuccessDiagnostics(store, "node-b", "node-a", now)

	diagnostics, ok := store.Snapshot("node-b", now)
	if !ok || diagnostics.LastUpdateSource != "node-a" {
		t.Fatalf("LastUpdateSource = %q, want node-a", diagnostics.LastUpdateSource)
	}
	if diagnostics.LastRelaySuppression != "" || diagnostics.LastRelaySuppressedAt != 0 {
		t.Fatalf("relay suppression was not cleared: %#v", diagnostics)
	}
}

func TestRelaySyncQueuesCompactCatalogSummary(t *testing.T) {
	state, config := buildTestNetworkState(t)
	config.Bootstrap = []syncConfigPeer{{ID: "node-c.catofes.", Addr: "127.0.0.1:33434"}}
	now := time.Unix(1000, 0)
	service := newTestDaemonService(&Runtime{Clock: func() time.Time { return now }}, state, config, defaultDaemonInterval)

	service.relaySyncToPeers("node-b.catofes.")

	select {
	case hostEvent := <-service.hostRuntime.Events():
		event, _ := service.hostRuntime.GossipSessionEventFor(hostEvent)
		timer, ok := event.(*gossip.SyncTimerEvent)
		if !ok {
			t.Fatalf("relay event = %T, want *SyncTimerEvent", event)
		}
		if timer.LocalSummary == nil {
			t.Fatal("relay event omitted local catalog summary")
		}
		view := service.StateStore.common.ReadView()
		digests := corestate.ZoneDigests(view.State.Network)
		wantRoot := corestate.CatalogRoot(digests)
		if !bytes.Equal(timer.LocalSummary.CatalogRoot, wantRoot) {
			t.Fatalf("relay summary root = %x, want %x", timer.LocalSummary.CatalogRoot, wantRoot)
		}
		if timer.LocalSummary.ZoneCount != len(digests) {
			t.Fatalf("relay summary zone count = %d, want projected digests", timer.LocalSummary.ZoneCount)
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
