package main

import (
	"fmt"
	"os"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
)

func debugPeer(peerID string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := daemonStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online peer_id=%s\n", response.PeerID)
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	config, err := rt.SyncConfig(state)
	if err != nil {
		return err
	}
	now := rt.Now()
	known := configuredKnownPeers(config)
	peerState := state.SyncPeers[peerID]
	source, configuredAddr := bootstrapPeerSource(config, peerID)
	endpoints := inspectPeerEndpoints(peerID, peerState, config, state.Network, now)
	resolved := "-"
	if addr := known[peerID]; addr != nil {
		resolved = addr.String()
	}
	if selected := selectedPeerEndpointAddr(endpoints); selected != "" {
		resolved = selected
	}
	return inspecttext.WritePeerDebug(os.Stdout, buildPeerDebugView(peerID, source, configuredAddr, resolved, peerState, now))
}

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
	return inspect.PeerDatagramStatsView{
		TooLargeDropped:           stats.TooLargeDropped,
		DigestOnlyAnnounces:       stats.DigestOnlyAnnounces,
		ChunkFallbacks:            stats.ChunkFallbacks,
		LastCatalogRootHex:        stats.LastCatalogRootHex,
		LastCatalogZoneCount:      stats.LastCatalogZoneCount,
		LastCatalogCursor:         stats.LastCatalogCursor,
		LastCatalogPageEntries:    stats.LastCatalogPageEntries,
		LastCatalogRejectedReason: stats.LastCatalogRejectedReason,
		LastCatalog:               formatUnixTime(stats.LastCatalogUnix),
		LastTooLarge:              formatUnixTime(stats.LastTooLargeUnix),
		LastTooLargeDirection:     stats.LastTooLargeDirection,
		LastTooLargeObject:        stats.LastTooLargeObject,
		LastTooLargeZone:          stats.LastTooLargeZone,
		LastTooLargeKey:           stats.LastTooLargeKey,
		LastTooLargeBytes:         stats.LastTooLargeBytes,
		LastTooLargeLimit:         stats.LastTooLargeLimit,
	}
}

func peerDebugObjectPullStats(peerState syncPeerState) inspect.PeerObjectPullStatsView {
	stats := peerState.ObjectPullStats
	if stats == nil {
		stats = &objectPullStats{}
	}
	return inspect.PeerObjectPullStatsView{
		Attempts:               stats.Attempts,
		Successes:              stats.Successes,
		Failures:               stats.Failures,
		LargeObjectUnreachable: stats.LargeObjectUnreachable,
		Last:                   formatUnixTime(stats.LastUnix),
		LastObject:             stats.LastObject,
		LastZone:               stats.LastZone,
		LastKey:                stats.LastKey,
		LastBytes:              stats.LastBytes,
		LastSourcePeer:         stats.LastSourcePeer,
		LastUnreachable:        stats.LastUnreachable,
		LastError:              stats.LastError,
	}
}

func peerDebugSyncFlow(peerState syncPeerState) inspect.PeerSyncFlowView {
	return inspect.PeerSyncFlowView{
		ActivePullState:     peerState.ActivePullState,
		ActivePullLastEvent: peerState.ActivePullLastEvent,
		ActivePullUpdated:   formatUnixTime(peerState.ActivePullUpdatedUnix),
		HintAccepted:        peerState.HintAccepted,
		HintSuppressed:      peerState.HintSuppressed,
		LastHint:            formatUnixTime(peerState.LastHintUnix),
		LastHintReason:      peerState.LastHintReason,
		LastHintSuppression: peerState.LastHintSuppression,
		ReadOnlyResponder:   peerState.ReadOnlyResponder,
		LastResponder:       formatUnixTime(peerState.LastResponderUnix),
		LastResponderKind:   peerState.LastResponderKind,
		LastResponderZone:   peerState.LastResponderZone,
	}
}

func bootstrapPeerSource(config *syncConfigFile, peerID string) (string, string) {
	for _, peer := range config.Bootstrap {
		if peer.ID == peerID {
			return "bootstrap", peer.Addr
		}
	}
	return "unknown", ""
}
