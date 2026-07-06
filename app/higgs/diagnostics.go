package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

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
	return inspect.PeerDebugView{
		PeerID:           peerID,
		Source:           source,
		ConfiguredAddr:   configuredAddr,
		ResolvedAddr:     resolved,
		Status:           peerStatus(peerState, now),
		LastSuccess:      formatLastSuccess(peerState),
		LastError:        peerState.LastError,
		Backoff:          formatBackoff(peerState, now),
		NextRetry:        formatNextRetry(peerState, now),
		KnownEndpoint:    resolved,
		DiscoveredAddr:   peerState.DiscoveredAddr,
		ObservedAddr:     peerState.ObservedAddr,
		ObservedStatus:   formatObservedPath(peerState, now),
		LastUpdateSource: peerState.LastUpdateSource,
		LastRelay:        formatUnixTime(peerState.LastRelayUnix),
		RelaySuppression: formatRelaySuppression(peerState),
		SyncFlow:         peerDebugSyncFlow(peerState),
		DatagramStats:    peerDebugDatagramStats(peerState),
		ObjectPullStats:  peerDebugObjectPullStats(peerState),
	}
}

func debugLinks(filter string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := linksStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		if response.Links == nil {
			return errors.New("daemon links_status response missing links")
		}
		fmt.Printf("daemon: online peer_id=%s link_instances=%d desired_links=%d last_link_error=%s\n",
			response.PeerID,
			response.Links.Inspection.Summary.LinkInstances,
			response.Links.Inspection.Summary.DesiredLinks,
			dash(response.Links.Inspection.Summary.LastError),
		)
		return writeDebugLinksFromBuild(os.Stdout, linkInspectionBuildFromControl(response.Links), filter)
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	return writeDebugLinks(os.Stdout, rt, state, filter)
}

func writeDebugLinks(w io.Writer, rt *Runtime, state *stateFile, filter string) error {
	build := buildLinkInspection(rt, state, nil)
	return writeDebugLinksFromBuild(w, build, filter)
}

func linkInspectionBuildFromControl(in *linkInspectionControl) linkInspectionBuild {
	if in == nil {
		return linkInspectionBuild{}
	}
	return linkInspectionBuild{
		Inspection:        in.Inspection,
		ReplannedDesired:  in.ReplannedDesired,
		ReplanIgnored:     in.ReplanIgnored,
		LastDesiredLinks:  in.LastDesiredLinks,
		DesiredPlanSource: in.DesiredPlanSource,
	}
}

func writeDebugLinksFromBuild(w io.Writer, build linkInspectionBuild, filter string) error {
	return inspecttext.WriteLinksDebug(w, inspect.LinksDebugView{
		Inspection:        build.Inspection,
		PlannedSpecs:      build.PlannedSpecs,
		ReplannedDesired:  build.ReplannedDesired,
		ReplanIgnored:     build.ReplanIgnored,
		LastDesiredLinks:  build.LastDesiredLinks,
		DesiredPlanSource: build.DesiredPlanSource,
		Filter:            filter,
	})
}

func filterLinkViews(links []inspect.LinkView, filter string) []inspect.LinkView {
	return inspect.FilterLinkViews(links, filter)
}

func debugLinkRoutingState(rt *Runtime, birdInstances map[string]*BirdInstanceState, groupID string) (state, neighborCount, bestRouteCount string) {
	state = "-"
	neighborCount = "-"
	bestRouteCount = "-"
	if rt == nil || rt.Config == nil || groupID == "" {
		return
	}
	// In the per-netns model, routing is configured at the netns level.
	// Map the overlay groupID → netns name and look up the BIRD instance by netns.
	netnsName := routingNetnsNameForLinkInstance(rt, groupID)
	if netnsName == "" {
		return
	}
	// Check if there's a routing instance for this netns.
	hasRoutingInstance := false
	for _, inst := range rt.Config.Routing.Instances {
		if inst.NetNS == netnsName && inst.Enabled {
			hasRoutingInstance = true
			break
		}
	}
	if !hasRoutingInstance {
		return
	}
	state = "pending"
	if birdInstances != nil {
		if inst := birdInstances[netnsName]; inst != nil {
			state = inst.State
			if state == "" {
				state = "pending"
			}
		}
	}
	return
}

func desiredByInstanceID(items []desiredLinkState) map[string]desiredLinkState {
	out := map[string]desiredLinkState{}
	for _, item := range items {
		if item.InstanceID != "" {
			out[item.InstanceID] = item
		}
	}
	return out
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

func debugZone(path zone.ZonePath) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	view, err := buildDebugZoneView(state, path, rt.Now())
	if err != nil {
		return err
	}
	return inspecttext.WriteZoneDebug(os.Stdout, view)
}

func buildDebugZoneView(state *stateFile, path zone.ZonePath, now time.Time) (inspect.ZoneDebugView, error) {
	configureValidation(state.Network)
	zs := state.Network.Zones[path]
	if zs == nil {
		return inspect.ZoneDebugView{}, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	digest := zoneDigest(state.Network, path)
	verifyResult := "ok"
	if err := higgscrypto.VerifyChain(state.Network, path, now); err != nil {
		verifyResult = err.Error()
	}
	revocation := state.Network.ActiveRevocation(path, now)
	var activeRevocation *inspect.RevocationView
	if revocation != nil {
		view := inspect.BuildRevocation(revocation)
		activeRevocation = &view
	}
	return inspect.ZoneDebugView{
		Detail: inspect.BuildZoneDetail(inspect.ZoneDetailInput{
			Path:           path,
			State:          zs,
			Network:        state.Network,
			Now:            now,
			IncludeHistory: false,
		}),
		RootHash:         hex.EncodeToString(digest.RootHash),
		VerifyResult:     verifyResult,
		ActiveRevocation: activeRevocation,
	}, nil
}

func debugRecords(path zone.ZonePath, prefix string, values bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	return writeDebugRecords(os.Stdout, state, path, prefix, values)
}

func writeDebugRecords(w io.Writer, state *stateFile, path zone.ZonePath, prefix string, values bool) error {
	if state == nil || state.Network == nil {
		return fmt.Errorf("state is nil")
	}
	if path.Valid() && state.Network.Zones[path] == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	return inspecttext.WriteRecordsDebug(w, inspect.BuildRecordsDebug(inspect.RecordsDebugInput{
		Network: state.Network,
		Path:    path,
		Prefix:  prefix,
	}), values)
}

func bootstrapPeerSource(config *syncConfigFile, peerID string) (string, string) {
	for _, peer := range config.Bootstrap {
		if peer.ID == peerID {
			return "bootstrap", peer.Addr
		}
	}
	return "unknown", ""
}

func zoneDigest(ns *zone.NetworkState, path zone.ZonePath) gossip.ZoneDigest {
	for _, digest := range gossip.ZoneDigests(ns) {
		if digest.Zone == path {
			return digest
		}
	}
	return gossip.ZoneDigest{Zone: path}
}

func countHistory(zs *zone.ZoneState) int {
	if zs == nil {
		return 0
	}
	var out int
	for _, records := range zs.RecordHistory {
		out += len(records)
	}
	return out
}

func formatLastSuccess(peerState syncPeerState) string {
	if peerState.LastSyncUnix == 0 {
		return "never"
	}
	return formatUnixTime(peerState.LastSyncUnix)
}

func peerStatus(peerState syncPeerState, now time.Time) string {
	if backoffRemaining(peerState, now) > 0 {
		return "backoff"
	}
	if peerState.LastError != "" {
		return "stale"
	}
	if peerState.LastSyncUnix == 0 {
		return "unknown"
	}
	if now.Sub(time.Unix(peerState.LastSyncUnix, 0)) > 2*time.Minute {
		return "stale"
	}
	return "online"
}

func formatBackoff(peerState syncPeerState, now time.Time) string {
	remaining := backoffRemaining(peerState, now)
	if remaining <= 0 {
		return "-"
	}
	return remaining.Round(time.Second).String()
}

func formatNextRetry(peerState syncPeerState, now time.Time) string {
	if backoffRemaining(peerState, now) <= 0 {
		return "-"
	}
	return formatUnixTime(peerState.BackoffUntilUnix)
}

func formatUnixTime(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

func formatRelaySuppression(peerState syncPeerState) string {
	if peerState.LastRelaySuppression == "" {
		return "-"
	}
	at := formatUnixTime(peerState.LastRelaySuppressedAt)
	if at == "never" {
		return peerState.LastRelaySuppression
	}
	return fmt.Sprintf("%s at=%s", peerState.LastRelaySuppression, at)
}

func formatObservedPath(peerState syncPeerState, now time.Time) string {
	if peerState.ObservedAddr == "" {
		return "-"
	}
	state := "expired"
	if observedPathActive(peerState, now) {
		state = "active"
	}
	return fmt.Sprintf("%s until=%s last_seen=%s last_success=%s failures=%d source=%s",
		state,
		formatUnixTime(peerState.ObservedUntilUnix),
		formatUnixTime(peerState.ObservedLastSeenUnix),
		formatUnixTime(peerState.ObservedLastSyncUnix),
		peerState.ObservedFailureCount,
		dash(peerState.ObservedSource),
	)
}

func debugEndpoints() error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	config, err := rt.SyncConfig(state)
	if err != nil {
		return err
	}
	port := listenPortFromAddr(config.ListenAddr)
	advertiseAddrs, reflectors := filterEndpointDiscoveryInputs(config, port)
	candidates, reflectorErr := collectSyncLocalEndpoints(port, advertiseAddrs, reflectors, config.ReflectorTimeout, config.FilterPrivateIPv4)
	localCandidates := make([]inspect.EndpointCandidateView, 0, len(candidates))
	for _, ep := range candidates {
		localCandidates = append(localCandidates, inspect.EndpointCandidateView{
			Address:  ep.IP.String(),
			Port:     ep.Port,
			Scope:    ep.Scope,
			Priority: ep.Priority,
			Source:   endpointSourceString(ep.Source),
		})
	}

	discovered := gossip.ExtractPeerEndpoints(state.Network)
	discoveredInput := make(map[string][]inspect.PeerSignedEndpoint, len(discovered))
	for peerID, endpoints := range discovered {
		for _, ep := range endpoints {
			discoveredInput[peerID] = append(discoveredInput[peerID], inspect.PeerSignedEndpoint{
				Address:      ep.Address,
				Port:         ep.Port,
				Scope:        ep.Scope,
				Priority:     ep.Priority,
				Protocol:     ep.Protocol,
				Source:       ep.Source,
				LastObserved: ep.LastObserved,
			})
		}
	}
	reflectorError := ""
	if reflectorErr != nil {
		reflectorError = reflectorErr.Error()
	}
	view := inspect.BuildEndpointDebug(inspect.EndpointDebugInput{
		ReflectorError:      reflectorError,
		HasPublicReflectors: len(gossip.ResolvePublicIPReflectors(reflectors)) > 0,
		LocalCandidates:     localCandidates,
		Discovered:          discoveredInput,
	})
	return inspecttext.WriteEndpointsDebug(os.Stdout, view)
}

func endpointSourceString(source gossip.LocalEndpointSource) string {
	switch source {
	case gossip.SourceAdvertise:
		return "advertise"
	case gossip.SourceInterface:
		return "interface"
	case gossip.SourceReflector:
		return "reflector"
	default:
		return "unknown"
	}
}

func debugAdmission() error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := admissionStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online peer_id=%s\n", response.PeerID)
		if response.Admission != nil {
			return inspecttext.WriteAdmissionDiagnosis(os.Stdout, *response.Admission)
		}
		fmt.Printf("admission: not available from daemon\n")
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	diagnosis := diagnoseAutoJoinAdmission(state, rt.Now())
	return inspecttext.WriteAdmissionDiagnosis(os.Stdout, diagnosis)
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
