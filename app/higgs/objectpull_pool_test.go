package main

import (
	"context"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func TestObjectPullPoolPullsZoneAsync(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
	now := time.Unix(1000, 0)
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "identity",
		Type:      "node.identity",
		Value:     []byte("node-b"),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}

	listener, err := objectPullTCPServe("127.0.0.1:0", objectPullLookup(func() *stateFile { return state }))
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("objectPullTCPServe: %v", err)
	}
	defer listener.Close()

	// Point bootstrap at the listener so the pool can resolve the TCP address.
	config := &syncConfigFile{
		Bootstrap: []syncConfigPeer{
			{ID: "node-b.catofes.", Addr: listener.Addr().String()},
		},
	}

	results := make(chan ObjectPullResult, 1)
	pool := newObjectPullPool(func() *stateFile { return state }, config, results, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool.Start(ctx)
	defer pool.Stop()

	if !pool.Submit(ctx, ObjectPullRequest{PeerID: "node-b.catofes.", Zone: "node-b.catofes."}) {
		t.Fatal("pool submit returned false")
	}

	select {
	case res := <-results:
		if res.Err != nil {
			t.Fatalf("object pull failed: %v", res.Err)
		}
		if res.Snapshot == nil || res.Snapshot.Zone != "node-b.catofes." {
			t.Fatalf("unexpected snapshot: %+v", res.Snapshot)
		}
		if len(res.Snapshot.Records) != 1 {
			t.Fatalf("expected 1 record, got %d", len(res.Snapshot.Records))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for object pull result")
	}
}

func TestObjectPullPoolReturnsErrorForUnreachable(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	config := &syncConfigFile{
		Bootstrap: []syncConfigPeer{
			{ID: "node-b.catofes.", Addr: "127.0.0.1:1"}, // unreachable port
		},
	}

	results := make(chan ObjectPullResult, 1)
	pool := newObjectPullPool(func() *stateFile { return state }, config, results, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool.Start(ctx)
	defer pool.Stop()

	if !pool.Submit(ctx, ObjectPullRequest{PeerID: "node-b.catofes.", Zone: "node-b.catofes."}) {
		t.Fatal("pool submit returned false")
	}

	select {
	case res := <-results:
		if res.Err == nil {
			t.Fatal("expected error for unreachable peer")
		}
		if res.Snapshot != nil {
			t.Fatal("expected nil snapshot on error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for object pull result")
	}
}

// Ensure ObjectPullResult can be mapped to SyncEvent ObjectPullResultEvent.
func TestObjectPullResultMapsToSyncEvent(t *testing.T) {
	res := ObjectPullResult{
		PeerID:   "peer-a",
		Zone:     "node-a.catofes.",
		Snapshot: &gossip.ZoneSnapshot{Zone: "node-a.catofes."},
	}
	ev := objectPullResultToEvent(res)
	ore, ok := ev.(*ObjectPullResultEvent)
	if !ok {
		t.Fatalf("expected ObjectPullResultEvent, got %T", ev)
	}
	if ore.PeerID != res.PeerID || ore.Zone != res.Zone {
		t.Fatalf("event mismatch: %+v", ore)
	}
}
