package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// handleObjectChunk keeps UDP assembly and transport repair outside the FSM,
// then returns the decoded snapshot to the active session. The session emits
// ApplySnapshotAction and waits for SnapshotAppliedEvent before completing.
func (d *DaemonService) handleObjectChunk(message *gossip.Message, limits corestate.SyncLimits) error {
	return d.handleObjectChunkFrom(message, nil, limits)
}

func (d *DaemonService) handleObjectChunkFrom(message *gossip.Message, replyAddr *net.UDPAddr, _ corestate.SyncLimits) error {
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
		_ = d.postSyncEvent(&gossip.ObjectChunkEvent{PeerID: message.PeerID, Zone: chunk.Zone, Err: err})
		return err
	}
	if !complete {
		if d.Sync.Transport != nil {
			udpChunkAssemblies.ScheduleRepair(message.PeerID, chunk, func(nack *gossip.ObjectChunkNACK) {
				msg := &gossip.Message{
					Type:            gossip.MessageObjectChunkNACK,
					ObjectChunkNACK: nack,
				}
				var err error
				if replyAddr != nil {
					err = d.Sync.Transport.SendTo(message.PeerID, replyAddr, msg)
				} else {
					err = d.Sync.Transport.Send(message.PeerID, msg)
				}
				if err == nil {
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
		_ = d.postSyncEvent(&gossip.ObjectChunkEvent{PeerID: message.PeerID, Zone: chunk.Zone, Err: err})
		return err
	}

	actualRoot := digestForSnapshot(snapshot).RootHash
	if len(chunk.RootHash) > 0 && !bytes.Equal(chunk.RootHash, actualRoot) {
		err := fmt.Errorf("chunk snapshot root mismatch for %s: advertised %x, decoded %x", snapshot.Zone, chunk.RootHash, actualRoot)
		d.recordObjectChunkRejectedDigest(message.PeerID, chunk, err, now)
		_ = d.postSyncEvent(&gossip.ObjectChunkEvent{PeerID: message.PeerID, Zone: chunk.Zone, Err: err})
		return err
	}
	recordDatagramChunkFallback(d.PeerObservability, message.PeerID, now)
	return d.postSyncEvent(&gossip.ObjectChunkEvent{PeerID: message.PeerID, Zone: chunk.Zone, Snapshot: snapshot})
}

func (d *DaemonService) recordObjectChunkRejectedDigest(peerID string, chunk *gossip.ObjectChunk, applyErr error, now time.Time) {
	if d == nil || d.StateStore == nil || peerID == "" || chunk == nil || chunk.Object != gossip.ObjectPullZone ||
		!chunk.Zone.Valid() || len(chunk.RootHash) == 0 {
		return
	}
	reason := gossip.RejectReason(applyErr)
	if reason == "" {
		reason = "verify_failed"
	}
	_, err := d.StateStore.UpdateCommonPeerCheckpoint(context.Background(), peerID, corestate.PeerCheckpointPatch{
		Reject: map[zone.ZonePath]corestate.RejectedObject{chunk.Zone: {
			RootHash: append([]byte(nil), chunk.RootHash...), Reason: reason,
			UpdatedUnix: now.Unix(), UntilUnix: now.Add(rejectedDigestTTL).Unix(),
		}},
	})
	if err != nil {
		d.logWarn("sync", "chunk_reject_state_commit_failed", map[string]any{
			"peer_id": peerID,
			"zone":    chunk.Zone,
			"error":   err,
		})
	}
}
