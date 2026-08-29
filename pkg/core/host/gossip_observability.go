package host

import (
	"encoding/hex"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func (runtime *Runtime) observeCatalogSummary(peerID string, summary *corestate.CatalogSummary, now time.Time) {
	if runtime == nil || summary == nil {
		return
	}
	runtime.Observability.Update(peerID, now, func(peer *observability.PeerDiagnostics) {
		if peer.DatagramStats == nil {
			peer.DatagramStats = &observability.PeerDatagramStats{}
		}
		peer.DatagramStats.LastCatalogUnix = now.Unix()
		peer.DatagramStats.LastCatalogRootHex = hex.EncodeToString(summary.CatalogRoot)
		peer.DatagramStats.LastCatalogZoneCount = summary.ZoneCount
		peer.DatagramStats.LastCatalogCursor = summary.NextCursor
		if summary.FirstPage != nil {
			peer.DatagramStats.LastCatalogPageEntries = len(summary.FirstPage.Entries)
		}
		peer.DatagramStats.LastCatalogRejectedReason = ""
	})
}

func (runtime *Runtime) observeCatalogPage(peerID string, page *corestate.CatalogPage, now time.Time) {
	if runtime == nil || page == nil {
		return
	}
	runtime.Observability.Update(peerID, now, func(peer *observability.PeerDiagnostics) {
		if peer.DatagramStats == nil {
			peer.DatagramStats = &observability.PeerDatagramStats{}
		}
		peer.DatagramStats.LastCatalogUnix = now.Unix()
		peer.DatagramStats.LastCatalogRootHex = hex.EncodeToString(page.CatalogRoot)
		peer.DatagramStats.LastCatalogCursor = page.NextCursor
		peer.DatagramStats.LastCatalogPageEntries = len(page.Entries)
		peer.DatagramStats.LastCatalogRejectedReason = ""
	})
}

func (runtime *Runtime) observeCatalogReject(peerID, cursor, reason string, now time.Time) {
	if runtime == nil {
		return
	}
	runtime.Observability.Update(peerID, now, func(peer *observability.PeerDiagnostics) {
		if peer.DatagramStats == nil {
			peer.DatagramStats = &observability.PeerDatagramStats{}
		}
		peer.DatagramStats.LastCatalogUnix = now.Unix()
		peer.DatagramStats.LastCatalogCursor = cursor
		peer.DatagramStats.LastCatalogRejectedReason = reason
	})
}

func (runtime *Runtime) observeReadOnlyResponder(peerID, kind string, path zone.ZonePath, now time.Time) {
	if runtime == nil {
		return
	}
	runtime.Observability.Update(peerID, now, func(peer *observability.PeerDiagnostics) {
		peer.ReadOnlyResponder++
		peer.LastResponderUnix = now.Unix()
		peer.LastResponderKind = kind
		peer.LastResponderZone = string(path)
	})
}

func (runtime *Runtime) observeSyncHint(peerID, reason, suppression string, accepted bool, now time.Time) {
	if runtime == nil {
		return
	}
	runtime.Observability.Update(peerID, now, func(peer *observability.PeerDiagnostics) {
		if accepted {
			peer.HintAccepted++
		} else {
			peer.HintSuppressed++
		}
		peer.LastHintUnix = now.Unix()
		peer.LastHintReason = reason
		peer.LastHintSuppression = suppression
	})
}

func (runtime *Runtime) observeActivePull(peerID, event string, session *gossip.SyncSession, now time.Time) {
	if runtime == nil {
		return
	}
	runtime.Observability.Update(peerID, now, func(peer *observability.PeerDiagnostics) {
		if session != nil {
			peer.ActivePullState = string(session.State)
		} else {
			peer.ActivePullState = ""
		}
		peer.ActivePullLastEvent = event
		peer.ActivePullUpdatedUnix = now.Unix()
	})
}

func (runtime *Runtime) observeDatagramTooLarge(peerID, object string, path zone.ZonePath, key string, size, limit int, now time.Time) {
	if runtime == nil {
		return
	}
	runtime.Observability.Update(peerID, now, func(peer *observability.PeerDiagnostics) {
		if peer.DatagramStats == nil {
			peer.DatagramStats = &observability.PeerDatagramStats{}
		}
		peer.DatagramStats.TooLargeDropped++
		peer.DatagramStats.LastTooLargeUnix = now.Unix()
		peer.DatagramStats.LastTooLargeDirection = "send"
		peer.DatagramStats.LastTooLargeObject = object
		peer.DatagramStats.LastTooLargeZone = string(path)
		peer.DatagramStats.LastTooLargeKey = key
		peer.DatagramStats.LastTooLargeBytes = size
		peer.DatagramStats.LastTooLargeLimit = limit
	})
}

func (runtime *Runtime) observeChunkFallback(peerID string, count int, now time.Time) {
	if runtime == nil || count <= 0 {
		return
	}
	runtime.Observability.Update(peerID, now, func(peer *observability.PeerDiagnostics) {
		if peer.DatagramStats == nil {
			peer.DatagramStats = &observability.PeerDatagramStats{}
		}
		peer.DatagramStats.ChunkFallbacks += int64(count)
	})
}

func (runtime *Runtime) observeChunkRepair(peerID string, ignored bool, chunks int, now time.Time) {
	if runtime == nil {
		return
	}
	runtime.Observability.Update(peerID, now, func(peer *observability.PeerDiagnostics) {
		if peer.DatagramStats == nil {
			peer.DatagramStats = &observability.PeerDatagramStats{}
		}
		if ignored {
			peer.DatagramStats.ChunkRepairIgnored++
		} else {
			peer.DatagramStats.ChunkRepairNACKs++
		}
		peer.DatagramStats.ChunkRepairChunks += int64(chunks)
	})
}

func (runtime *Runtime) observeObjectPullAttempt(peerID string, path zone.ZonePath, now time.Time) {
	if runtime == nil {
		return
	}
	runtime.Observability.Update(peerID, now, func(peer *observability.PeerDiagnostics) {
		if peer.ObjectPullStats == nil {
			peer.ObjectPullStats = &observability.PeerObjectPullStats{}
		}
		stats := peer.ObjectPullStats
		stats.Attempts++
		stats.LastUnix = now.Unix()
		stats.LastObject = "zone"
		stats.LastZone = string(path)
		stats.LastSourcePeer = peerID
		stats.LastUnreachable = false
	})
}

func (runtime *Runtime) observeObjectPullResult(result GossipObjectPullCompletion, now time.Time) {
	if runtime == nil {
		return
	}
	runtime.Observability.Update(result.PeerID, now, func(peer *observability.PeerDiagnostics) {
		if peer.ObjectPullStats == nil {
			peer.ObjectPullStats = &observability.PeerObjectPullStats{}
		}
		stats := peer.ObjectPullStats
		stats.LastUnix = now.Unix()
		stats.LastObject = "zone"
		stats.LastZone = string(result.Zone)
		stats.LastBytes = result.Bytes
		stats.LastSourcePeer = result.PeerID
		stats.LastUnreachable = result.Unreachable
		if result.Err != nil {
			stats.Failures++
			stats.LastError = result.Err.Error()
			if result.Unreachable {
				stats.LargeObjectUnreachable++
			}
			return
		}
		stats.Successes++
		stats.LastError = ""
	})
}
