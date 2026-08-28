package main

import (
	"time"

	"github.com/HiggsNet/photon/internal/observability"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func recordObjectPullAttempt(store *observability.PeerObservabilityStore, peerID, object string, zoneName zone.ZonePath, key string, now time.Time) {
	if store == nil || peerID == "" {
		return
	}
	store.Update(peerID, now, func(snapshot *observability.PeerDiagnostics) {
		if snapshot.ObjectPullStats == nil {
			snapshot.ObjectPullStats = &objectPullStats{}
		}
		stats := snapshot.ObjectPullStats
		stats.Attempts++
		stats.LastUnix = now.Unix()
		stats.LastObject = object
		stats.LastZone = string(zoneName)
		stats.LastKey = key
		stats.LastSourcePeer = peerID
		stats.LastUnreachable = false
	})
}

func recordObjectPullResult(store *observability.PeerObservabilityStore, peerID, object string, zoneName zone.ZonePath, key string, bytes int, err error, unreachable bool, now time.Time) {
	if store == nil || peerID == "" {
		return
	}
	store.Update(peerID, now, func(snapshot *observability.PeerDiagnostics) {
		if snapshot.ObjectPullStats == nil {
			snapshot.ObjectPullStats = &objectPullStats{}
		}
		stats := snapshot.ObjectPullStats
		stats.LastUnix = now.Unix()
		stats.LastObject = object
		stats.LastZone = string(zoneName)
		stats.LastKey = key
		stats.LastBytes = bytes
		stats.LastSourcePeer = peerID
		stats.LastUnreachable = unreachable
		if err != nil {
			stats.Failures++
			stats.LastError = err.Error()
			if unreachable {
				stats.LargeObjectUnreachable++
			}
			return
		}
		stats.Successes++
		stats.LastError = ""
	})
}

func (d *DaemonService) observeObjectPullAttempt(peerID string, path zone.ZonePath, now time.Time) {
	if d != nil {
		recordObjectPullAttempt(d.PeerObservability, peerID, "zone", path, "", now)
	}
}

func (d *DaemonService) observeObjectPullResult(result corehost.GossipObjectPullDiagnostics) {
	if d != nil && d.Sync != nil {
		recordObjectPullResult(d.PeerObservability, result.PeerID, "zone", result.Zone, "", result.Bytes, result.Err, result.Unreachable, result.At)
	}
}

func syncDebugLogger(config *syncConfigFile) func(gossip.Event) {
	if !debugLogEnabled(config) {
		return nil
	}
	logger := newAppLogger(config)
	return func(event gossip.Event) {
		fields := map[string]any{
			"direction":    event.Direction,
			"peer_id":      event.PeerID,
			"message_type": event.Type,
			"addr":         event.Addr,
			"bytes":        event.Bytes,
			"zones":        event.Zones,
			"records":      event.Records,
			"duration_ms":  event.Duration.Milliseconds(),
		}
		if event.Reason != "" {
			fields["reject_reason"] = event.Reason
		}
		if event.Error != "" {
			fields["error"] = event.Error
		}
		if event.QuotaRequestedBytes > 0 || event.QuotaRequestedObjects > 0 {
			fields["quota_requested_bytes"] = event.QuotaRequestedBytes
			fields["quota_requested_objects"] = event.QuotaRequestedObjects
			fields["quota_available_bytes"] = event.QuotaAvailableBytes
			fields["quota_available_objects"] = event.QuotaAvailableObjects
			fields["quota_byte_rate"] = event.QuotaByteRate
			fields["quota_byte_burst"] = event.QuotaByteBurst
			fields["quota_object_rate"] = event.QuotaObjectRate
			fields["quota_object_burst"] = event.QuotaObjectBurst
			if event.QuotaLastRefillUnixNano > 0 {
				fields["quota_last_refill"] = time.Unix(0, event.QuotaLastRefillUnixNano).UTC().Format(time.RFC3339Nano)
			}
		}
		logger.Debug("gossip", "message", fields)
	}
}

func debugLogEnabled(config *syncConfigFile) bool {
	return newAppLogger(config).debugEnabled()
}
