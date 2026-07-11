package main

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
)

func testSentChunks(transferID []byte) []*gossip.ObjectChunk {
	chunks := make([]*gossip.ObjectChunk, 3)
	for i := range chunks {
		chunks[i] = &gossip.ObjectChunk{TransferID: transferID, Object: gossip.ObjectPullZone, Zone: "catofes.", ObjectHash: make([]byte, 32), Index: uint16(i), Total: 3, Data: []byte{byte(i)}}
	}
	return chunks
}

func TestSentChunkCacheRepairsMissingWithoutDuplicateAmplification(t *testing.T) {
	now := time.Unix(100, 0)
	id := []byte("0123456789abcdef")
	cache := newSentChunkCache()
	if !cache.put("peer-a", id, testSentChunks(id), now) {
		t.Fatal("put rejected")
	}
	nack := &gossip.ObjectChunkNACK{TransferID: id, Missing: []uint16{2, 0}}
	got := cache.repair("peer-a", nack, now)
	if len(got) != 2 || got[0].Index != 0 || got[1].Index != 2 {
		t.Fatalf("repair = %#v", got)
	}
	if duplicate := cache.repair("peer-a", nack, now); len(duplicate) != 0 {
		t.Fatalf("duplicate repair sent %d chunks", len(duplicate))
	}
}

func TestSentChunkCacheRejectsWrongOrExpiredTransfer(t *testing.T) {
	now := time.Unix(100, 0)
	id := []byte("0123456789abcdef")
	cache := newSentChunkCache()
	if !cache.put("peer-a", id, testSentChunks(id), now) {
		t.Fatal("put rejected")
	}
	if got := cache.repair("peer-a", &gossip.ObjectChunkNACK{TransferID: []byte("fedcba9876543210"), Missing: []uint16{0}}, now); len(got) != 0 {
		t.Fatal("wrong transfer id repaired")
	}
	if got := cache.repair("peer-a", &gossip.ObjectChunkNACK{TransferID: id, Missing: []uint16{0}}, now.Add(chunkTransferTTL)); len(got) != 0 {
		t.Fatal("expired transfer repaired")
	}
}

func TestMissingChunkIndexesIsBounded(t *testing.T) {
	chunks := make([][]byte, maxChunkNACKIndexes+10)
	chunks[1] = []byte("present")
	got := missingChunkIndexes(chunks, maxChunkNACKIndexes)
	if len(got) != maxChunkNACKIndexes {
		t.Fatalf("missing = %d", len(got))
	}
	if got[0] != 0 || got[1] != 2 {
		t.Fatalf("missing starts with %v", got[:2])
	}
}

func TestChunkAssemblyQuietNACKRepairsOutOfOrderLoss(t *testing.T) {
	id := []byte("0123456789abcdef")
	data := []byte("zero-one-two")
	hash := sha256.Sum256(data)
	chunks := []*gossip.ObjectChunk{
		{TransferID: id, Object: gossip.ObjectPullZone, Zone: "catofes.", ObjectHash: hash[:], Index: 0, Total: 3, Data: []byte("zero-")},
		{TransferID: id, Object: gossip.ObjectPullZone, Zone: "catofes.", ObjectHash: hash[:], Index: 1, Total: 3, Data: []byte("one-")},
		{TransferID: id, Object: gossip.ObjectPullZone, Zone: "catofes.", ObjectHash: hash[:], Index: 2, Total: 3, Data: []byte("two")},
	}
	store := newChunkAssemblyStore()
	nacks := make(chan *gossip.ObjectChunkNACK, 1)
	for _, index := range []int{2, 0} {
		if _, complete, err := store.add("peer-a", chunks[index], time.Now()); err != nil || complete {
			t.Fatalf("add[%d]: complete=%t err=%v", index, complete, err)
		}
		store.scheduleRepair("peer-a", chunks[index], func(nack *gossip.ObjectChunkNACK) { nacks <- nack })
	}
	select {
	case nack := <-nacks:
		if len(nack.Missing) != 1 || nack.Missing[0] != 1 {
			t.Fatalf("nack = %#v", nack)
		}
	case <-time.After(time.Second):
		t.Fatal("repair NACK not emitted after quiet period")
	}
	got, complete, err := store.add("peer-a", chunks[1], time.Now())
	if err != nil || !complete || string(got) != string(data) {
		t.Fatalf("repair completion: data=%q complete=%t err=%v", got, complete, err)
	}
}

func TestChunkAssemblyDropPeerEnforcesRoundDeadline(t *testing.T) {
	id := []byte("0123456789abcdef")
	chunk := &gossip.ObjectChunk{TransferID: id, Object: gossip.ObjectPullZone, Zone: "catofes.", ObjectHash: make([]byte, 32), Index: 0, Total: 2, Data: []byte("partial")}
	store := newChunkAssemblyStore()
	if _, _, err := store.add("peer-a", chunk, time.Now()); err != nil {
		t.Fatal(err)
	}
	store.dropPeer("peer-a")
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.entries) != 0 {
		t.Fatalf("assemblies after deadline = %d", len(store.entries))
	}
}
