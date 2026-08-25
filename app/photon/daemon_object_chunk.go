package main

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

// handleObjectChunk keeps UDP assembly and transport repair outside the FSM,
// then returns the decoded snapshot to the active session. The session emits
// ApplySnapshotAction and waits for SnapshotAppliedEvent before completing.
func (d *DaemonService) handleObjectChunk(message *gossip.Message, _ gossip.SyncLimits) error {
	if d == nil || d.Sync == nil {
		return errors.New("daemon service is not initialized")
	}
	if message == nil || message.ObjectChunk == nil {
		return nil
	}

	chunk := message.ObjectChunk
	now := d.Sync.now()
	data, complete, err := udpChunkAssemblies.add(message.PeerID, chunk, now)
	if err != nil {
		d.recordObjectChunkRejectedDigest(message.PeerID, chunk, err, now)
		_ = d.postSyncEvent(&ObjectChunkEvent{PeerID: message.PeerID, Zone: chunk.Zone, Err: err})
		return err
	}
	if !complete {
		if d.Sync.Transport != nil {
			udpChunkAssemblies.scheduleRepair(message.PeerID, chunk, func(nack *gossip.ObjectChunkNACK) {
				if err := d.Sync.Transport.Send(message.PeerID, &gossip.Message{
					Type:            gossip.MessageObjectChunkNACK,
					ObjectChunkNACK: nack,
				}); err == nil {
					recordDatagramRepairNACK(d.PeerObservability, message.PeerID, false, d.Sync.now())
				}
			})
		}
		return nil
	}

	if chunk.Object != gossip.ObjectPullZone {
		return nil
	}
	snapshot, err := gossip.DecodeZoneSnapshotObject(data)
	if err != nil {
		d.recordObjectChunkRejectedDigest(message.PeerID, chunk, err, now)
		_ = d.postSyncEvent(&ObjectChunkEvent{PeerID: message.PeerID, Zone: chunk.Zone, Err: err})
		return err
	}

	actualRoot := digestForSnapshot(snapshot).RootHash
	if len(chunk.RootHash) > 0 && !bytes.Equal(chunk.RootHash, actualRoot) {
		err := fmt.Errorf("chunk snapshot root mismatch for %s: advertised %x, decoded %x", snapshot.Zone, chunk.RootHash, actualRoot)
		d.recordObjectChunkRejectedDigest(message.PeerID, chunk, err, now)
		_ = d.postSyncEvent(&ObjectChunkEvent{PeerID: message.PeerID, Zone: chunk.Zone, Err: err})
		return err
	}
	recordDatagramChunkFallback(d.PeerObservability, message.PeerID, now)
	return d.postSyncEvent(&ObjectChunkEvent{PeerID: message.PeerID, Zone: chunk.Zone, Snapshot: snapshot})
}

func (d *DaemonService) recordObjectChunkRejectedDigest(peerID string, chunk *gossip.ObjectChunk, applyErr error, now time.Time) {
	if d == nil || d.StateStore == nil || peerID == "" || chunk == nil || chunk.Object != gossip.ObjectPullZone ||
		!chunk.Zone.Valid() || len(chunk.RootHash) == 0 {
		return
	}
	if _, err := d.StateStore.UpdateSyncPeer(peerID, func(peer *syncPeerState) error {
		state := &stateFile{SyncPeers: map[string]syncPeerState{peerID: *peer}}
		recordRejectedDigest(state, peerID, gossip.ZoneDigest{
			Zone:     chunk.Zone,
			RootHash: chunk.RootHash,
		}, gossip.RejectReason(applyErr), now)
		*peer = state.SyncPeers[peerID]
		return nil
	}); err != nil {
		d.logWarn("sync", "chunk_reject_state_commit_failed", map[string]any{
			"peer_id": peerID,
			"zone":    chunk.Zone,
			"error":   err,
		})
		return
	}
	d.markMetadataCheckpointDirty()
}
