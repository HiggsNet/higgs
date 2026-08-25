package main

import (
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestObjectPullPoolPullsZoneAsync(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	now := time.Unix(1000, 0)
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "identity",
		Type:      "node.identity",
		Value:     []byte("node-b"),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := photoncrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
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

	results := make(chan ObjectPullResult, 1)
	pool := newObjectPullPool(results, 1)
	ctx := t.Context()
	pool.Start(ctx)
	defer pool.Stop()

	if !pool.Submit(ctx, ObjectPullRequest{PeerID: "node-b.catofes.", Zone: "node-b.catofes.", Addr: listener.Addr().String()}) {
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
	results := make(chan ObjectPullResult, 1)
	pool := newObjectPullPool(results, 1)
	ctx := t.Context()
	pool.Start(ctx)
	defer pool.Stop()

	if !pool.Submit(ctx, ObjectPullRequest{PeerID: "node-b.catofes.", Zone: "node-b.catofes.", Addr: "127.0.0.1:1"}) {
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
