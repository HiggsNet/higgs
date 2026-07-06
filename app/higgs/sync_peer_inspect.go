package main

import (
	"time"

	"github.com/Catofes/higgs/internal/inspect"
)

func buildPeerDebugView(peerID, source, configuredAddr, resolved string, peerState syncPeerState, now time.Time) inspect.PeerDebugView {
	return inspect.BuildPeerDebug(peerDebugInput(peerID, source, configuredAddr, resolved, peerState, now))
}

func peerDebugInput(peerID, source, configuredAddr, resolved string, peerState syncPeerState, now time.Time) inspect.PeerDebugInput {
	return inspect.PeerDebugInput{
		PeerID:                peerID,
		Source:                source,
		ConfiguredAddr:        configuredAddr,
		ResolvedAddr:          resolved,
		LastSyncUnix:          peerState.LastSyncUnix,
		LastError:             peerState.LastError,
		BackoffUntilUnix:      peerState.BackoffUntilUnix,
		DiscoveredAddr:        peerState.DiscoveredAddr,
		ObservedAddr:          peerState.ObservedAddr,
		ObservedUntilUnix:     peerState.ObservedUntilUnix,
		ObservedLastSeenUnix:  peerState.ObservedLastSeenUnix,
		ObservedLastSyncUnix:  peerState.ObservedLastSyncUnix,
		ObservedFailureCount:  peerState.ObservedFailureCount,
		ObservedSource:        peerState.ObservedSource,
		LastUpdateSource:      peerState.LastUpdateSource,
		LastRelayUnix:         peerState.LastRelayUnix,
		LastRelaySuppression:  peerState.LastRelaySuppression,
		LastRelaySuppressedAt: peerState.LastRelaySuppressedAt,
		SyncFlow:              peerDebugSyncFlow(peerState),
		DatagramStats:         peerDebugDatagramStats(peerState),
		ObjectPullStats:       peerDebugObjectPullStats(peerState),
		Now:                   now,
	}
}

func peerDebugDatagramStats(peerState syncPeerState) inspect.PeerDatagramStatsView {
	stats := peerState.DatagramStats
	if stats == nil {
		stats = &datagramStats{}
	}
	return inspect.BuildPeerDatagramStatsView(inspect.PeerDatagramStatsInput{
		TooLargeDropped:           stats.TooLargeDropped,
		DigestOnlyAnnounces:       stats.DigestOnlyAnnounces,
		ChunkFallbacks:            stats.ChunkFallbacks,
		LastCatalogUnix:           stats.LastCatalogUnix,
		LastCatalogRootHex:        stats.LastCatalogRootHex,
		LastCatalogZoneCount:      stats.LastCatalogZoneCount,
		LastCatalogCursor:         stats.LastCatalogCursor,
		LastCatalogPageEntries:    stats.LastCatalogPageEntries,
		LastCatalogRejectedReason: stats.LastCatalogRejectedReason,
		LastTooLargeUnix:          stats.LastTooLargeUnix,
		LastTooLargeDirection:     stats.LastTooLargeDirection,
		LastTooLargeObject:        stats.LastTooLargeObject,
		LastTooLargeZone:          stats.LastTooLargeZone,
		LastTooLargeKey:           stats.LastTooLargeKey,
		LastTooLargeBytes:         stats.LastTooLargeBytes,
		LastTooLargeLimit:         stats.LastTooLargeLimit,
	})
}

func peerDebugObjectPullStats(peerState syncPeerState) inspect.PeerObjectPullStatsView {
	stats := peerState.ObjectPullStats
	if stats == nil {
		stats = &objectPullStats{}
	}
	return inspect.BuildPeerObjectPullStatsView(inspect.PeerObjectPullStatsInput{
		Attempts:               stats.Attempts,
		Successes:              stats.Successes,
		Failures:               stats.Failures,
		LargeObjectUnreachable: stats.LargeObjectUnreachable,
		LastUnix:               stats.LastUnix,
		LastObject:             stats.LastObject,
		LastZone:               stats.LastZone,
		LastKey:                stats.LastKey,
		LastBytes:              stats.LastBytes,
		LastSourcePeer:         stats.LastSourcePeer,
		LastUnreachable:        stats.LastUnreachable,
		LastError:              stats.LastError,
	})
}

func peerDebugSyncFlow(peerState syncPeerState) inspect.PeerSyncFlowView {
	return inspect.BuildPeerSyncFlowView(inspect.PeerSyncFlowInput{
		ActivePullState:       peerState.ActivePullState,
		ActivePullLastEvent:   peerState.ActivePullLastEvent,
		ActivePullUpdatedUnix: peerState.ActivePullUpdatedUnix,
		HintAccepted:          peerState.HintAccepted,
		HintSuppressed:        peerState.HintSuppressed,
		LastHintUnix:          peerState.LastHintUnix,
		LastHintReason:        peerState.LastHintReason,
		LastHintSuppression:   peerState.LastHintSuppression,
		ReadOnlyResponder:     peerState.ReadOnlyResponder,
		LastResponderUnix:     peerState.LastResponderUnix,
		LastResponderKind:     peerState.LastResponderKind,
		LastResponderZone:     peerState.LastResponderZone,
	})
}
