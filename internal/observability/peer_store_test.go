package observability

import (
	"fmt"
	"sync"
	"testing"
	"time"

	higgsstate "github.com/Catofes/higgs/internal/state"
)

func TestPeerStoreSnapshotIsDetachedAndConcurrent(t *testing.T) {
	store := NewPeerObservabilityStore(8, time.Hour)
	now := time.Unix(100, 0)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				store.Update("peer-a", now, func(snapshot *PeerSnapshot) {
					if snapshot.DatagramStats == nil {
						snapshot.DatagramStats = &higgsstate.PeerDatagramStats{}
					}
					snapshot.DatagramStats.ChunkFallbacks++
				})
			}
		}()
	}
	wg.Wait()

	snapshot, ok := store.Snapshot("peer-a", now)
	if !ok || snapshot.DatagramStats == nil || snapshot.DatagramStats.ChunkFallbacks != 800 {
		t.Fatalf("snapshot = %#v, want 800 fallbacks", snapshot)
	}
	snapshot.DatagramStats.ChunkFallbacks = 0
	again, _ := store.Snapshot("peer-a", now)
	if again.DatagramStats.ChunkFallbacks != 800 {
		t.Fatalf("stored snapshot was mutated through returned pointer: %#v", again)
	}
}

func TestPeerStoreBoundsDeletesAndExpiresEntries(t *testing.T) {
	store := NewPeerObservabilityStore(2, time.Minute)
	base := time.Unix(100, 0)
	update := func(peerID string, now time.Time) {
		store.Update(peerID, now, func(snapshot *PeerSnapshot) {
			snapshot.ObjectPullStats = &higgsstate.PeerObjectPullStats{LastSourcePeer: peerID}
		})
	}
	update("peer-b", base)
	update("peer-a", base)
	update("peer-c", base.Add(time.Second))

	if _, ok := store.Snapshot("peer-a", base.Add(time.Second)); ok {
		t.Fatal("peer-a was not evicted by deterministic oldest-entry bound")
	}
	if got := store.Len(base.Add(time.Second)); got != 2 {
		t.Fatalf("len = %d, want 2", got)
	}
	store.Delete("peer-b")
	if _, ok := store.Snapshot("peer-b", base.Add(time.Second)); ok {
		t.Fatal("deleted peer-b is still present")
	}
	if purged := store.PurgeExpired(base.Add(2 * time.Minute)); purged != 1 {
		t.Fatalf("purged = %d, want 1", purged)
	}
}

func TestPeerStoreSnapshotsAreDetached(t *testing.T) {
	store := NewPeerObservabilityStore(4, 0)
	now := time.Unix(100, 0)
	for i := 0; i < 2; i++ {
		peerID := fmt.Sprintf("peer-%d", i)
		store.Update(peerID, now, func(snapshot *PeerSnapshot) {
			snapshot.DatagramStats = &higgsstate.PeerDatagramStats{ChunkRepairChunks: 2}
		})
	}
	all := store.Snapshots(now)
	all["peer-0"].DatagramStats.ChunkRepairChunks = 99
	snapshot, _ := store.Snapshot("peer-0", now)
	if snapshot.DatagramStats.ChunkRepairChunks != 2 {
		t.Fatalf("stored snapshot was mutated through map snapshot: %#v", snapshot)
	}
}
