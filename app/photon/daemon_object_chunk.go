package main

import (
	"errors"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// handleObjectChunk keeps UDP assembly and transport repair outside the
// committed state transaction, then applies a completed snapshot through the
// daemon StateStore. The non-daemon SyncRuntime path retains its standalone
// implementation for sync-once compatibility.
func (d *DaemonService) handleObjectChunk(message *gossip.Message, limits corestate.SyncLimits) error {
	if d == nil || d.Sync == nil {
		return errors.New("daemon service is not initialized")
	}
	if message == nil || message.ObjectChunk == nil {
		return nil
	}

	chunk := message.ObjectChunk
	now := d.Sync.now()
	data, complete, err := udpChunkAssemblies.Add(message.PeerID, chunk, now)
	if err != nil {
		d.recordObjectChunkRejectedDigest(message.PeerID, chunk, err, now)
		return err
	}
	if !complete {
		if d.Sync.Transport != nil {
			udpChunkAssemblies.ScheduleRepair(message.PeerID, chunk, func(nack *gossip.ObjectChunkNACK) {
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
		return err
	}

	pullLimits := limits
	pullLimits.MaxBytes = gossip.MaxChunkObjectBytes
	result, applied, err := d.applySyncSnapshotAction(message.PeerID, gossip.ApplySnapshotAction{
		PeerID:        message.PeerID,
		Snapshot:      snapshot,
		RelaxedLimits: true,
	}, pullLimits, now)
	if err != nil {
		return err
	}
	if !applied {
		return nil
	}

	recordDatagramChunkFallback(d.PeerObservability, message.PeerID, now)
	d.logInfo("sync", "zone_applied", map[string]any{
		"peer_id":     message.PeerID,
		"zone":        result.Zone,
		"records":     result.Records,
		"delegations": result.Delegation,
		"via":         "udp_chunks",
	})
	return d.saveCommittedState()
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
}
