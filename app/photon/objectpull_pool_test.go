package main

import (
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestDaemonObjectPullWorkerPullsZone(t *testing.T) {
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

	config := &syncConfigFile{Bootstrap: []syncConfigPeer{{ID: "node-b.catofes.", Addr: listener.Addr().String()}}}
	service := newTestDaemonService(&Runtime{}, state, config, time.Second)
	completion := (daemonObjectPullWorker{daemon: service}).PullGossipObject(t.Context(), gossip.StartObjectPullAction{PeerID: "node-b.catofes.", Zone: "node-b.catofes."})
	if completion.Err != nil {
		t.Fatalf("object pull failed: %v", completion.Err)
	}
	if completion.Snapshot == nil || completion.Snapshot.Zone != "node-b.catofes." {
		t.Fatalf("unexpected snapshot: %+v", completion.Snapshot)
	}
	if len(completion.Snapshot.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(completion.Snapshot.Records))
	}
}

func TestDaemonObjectPullWorkerReturnsErrorForUnreachable(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	config := &syncConfigFile{Bootstrap: []syncConfigPeer{{ID: "node-b.catofes.", Addr: "127.0.0.1:1"}}}
	service := newTestDaemonService(&Runtime{}, state, config, time.Second)
	completion := (daemonObjectPullWorker{daemon: service}).PullGossipObject(t.Context(), gossip.StartObjectPullAction{PeerID: "node-b.catofes.", Zone: "node-b.catofes."})
	if completion.Err == nil {
		t.Fatal("expected error for unreachable peer")
	}
	if completion.Snapshot != nil {
		t.Fatal("expected nil snapshot on error")
	}
}
