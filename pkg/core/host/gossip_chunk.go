package host

import (
	"encoding/hex"
	"errors"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

const GossipChunkRepairNamespace = "gossip_chunk_repair"

var ErrGossipChunkStoreUnavailable = errors.New("gossip chunk store is unavailable")

// AddGossipObjectChunk adds one UDP chunk to this host's bounded in-memory
// assembly store. Chunk state is scoped to one Runtime and never persisted.
func (runtime *Runtime) AddGossipObjectChunk(peerID string, chunk *gossip.ObjectChunk, now time.Time) ([]byte, bool, error) {
	if runtime == nil || runtime.gossipChunks == nil {
		return nil, false, ErrGossipChunkStoreUnavailable
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if runtime.stopped {
		return nil, false, ErrRuntimeStopped
	}
	scheduler := runtime.scheduler
	data, complete, err := runtime.gossipChunks.Add(peerID, chunk, now)
	if complete && chunk != nil {
		scheduler.Cancel(gossipChunkRepairTimerID(peerID, chunk.TransferID))
	}
	return data, complete, err
}

// ScheduleGossipChunkRepair puts the gossip-selected quiet deadline onto the
// one HostRuntime scheduler. No protocol package creates a timer or goroutine.
func (runtime *Runtime) ScheduleGossipChunkRepair(peerID string, chunk *gossip.ObjectChunk) error {
	if runtime == nil || runtime.gossipChunks == nil {
		return ErrGossipChunkStoreUnavailable
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if runtime.stopped {
		return ErrRuntimeStopped
	}
	scheduler := runtime.scheduler
	deadline, ok := runtime.gossipChunks.RepairDeadline(peerID, chunk)
	if !ok {
		return nil
	}
	_, err := scheduler.Schedule(gossipChunkRepairTimerID(peerID, chunk.TransferID), deadline)
	return err
}

func (runtime *Runtime) dropGossipPeerChunks(peerID string) {
	if runtime != nil && runtime.gossipChunks != nil {
		runtime.gossipChunks.DropPeer(peerID)
		runtime.schedulerForRead().CancelOwner(GossipChunkRepairNamespace, peerID)
	}
}

func gossipChunkRepairTimerID(peerID string, transferID []byte) TimerID {
	return TimerID{Namespace: GossipChunkRepairNamespace, Owner: peerID, Key: hex.EncodeToString(transferID)}
}
