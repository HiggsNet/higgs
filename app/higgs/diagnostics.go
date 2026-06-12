package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
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
	resolved := "-"
	if addr := known[peerID]; addr != nil {
		resolved = addr.String()
	}
	if peerState.DiscoveredAddr != "" {
		resolved = peerState.DiscoveredAddr
	}
	fmt.Printf("peer_id: %s\n", peerID)
	fmt.Printf("source: %s\n", source)
	fmt.Printf("configured_addr: %s\n", dash(configuredAddr))
	fmt.Printf("resolved_addr: %s\n", resolved)
	fmt.Printf("status: %s\n", peerStatus(peerState, now))
	fmt.Printf("last_success: %s\n", formatLastSuccess(peerState))
	fmt.Printf("last_error: %s\n", dash(peerState.LastError))
	fmt.Printf("backoff: %s\n", formatBackoff(peerState, now))
	fmt.Printf("next_retry: %s\n", formatNextRetry(peerState, now))
	fmt.Printf("known_endpoint: %s\n", resolved)
	fmt.Printf("discovered_addr: %s\n", dash(peerState.DiscoveredAddr))
	fmt.Printf("observed_addr: %s\n", dash(peerState.ObservedAddr))
	fmt.Printf("observed_status: %s\n", formatObservedPath(peerState, now))
	fmt.Printf("last_update_source: %s\n", dash(peerState.LastUpdateSource))
	fmt.Printf("last_relay: %s\n", formatUnixTime(peerState.LastRelayUnix))
	fmt.Printf("relay_suppression: %s\n", formatRelaySuppression(peerState))
	printDebugPeerDatagramStats(peerState)
	printDebugPeerObjectPullStats(peerState)
	return nil
}

func debugLinks() error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := daemonStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online peer_id=%s link_instances=%d desired_links=%d last_link_error=%s\n",
			response.PeerID,
			response.LinkInstances,
			response.DesiredLinks,
			dash(response.LastLinkError),
		)
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	return writeDebugLinks(os.Stdout, rt, state)
}

func writeDebugLinks(w io.Writer, rt *Runtime, state *stateFile) error {
	reconcile := state.IPsecReconcile
	if reconcile == nil {
		reconcile = &ipsecReconcileState{}
	}
	plannedDesired := map[string]desiredLinkState{}
	if rt != nil && rt.Config != nil && state != nil && state.Network != nil && !state.ManagedZone.IsRoot() && state.ManagedZone.Valid() && len(rt.Config.IPsec.LinkGroups) > 0 {
		plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, rt.Config.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: rt.Now()})
		if err != nil {
			fmt.Fprintf(w, "desired_plan_error: %s\n", err)
		} else {
			for _, spec := range plan.Desired {
				item := desiredLinkState{
					InstanceID:      ipsec.LinkInstanceID(spec),
					GroupID:         spec.OverlayID,
					PeerZone:        spec.PeerZone,
					TransportID:     spec.TransportID,
					DesiredSpecHash: ipsec.TransportLinkSpecHash(spec),
					InterfaceName:   spec.InterfaceName,
					XFRMIfID:        spec.XFRMIfID,
					Endpoint:        summarizeContactEndpoint(spec.ContactPoints),
					LocalTunnelAddr: ipsec.FormatScopedTunnelAddress(spec.LocalTunnelAddr, spec.InterfaceName, spec.NetNS),
					PeerTunnelAddr:  ipsec.FormatScopedTunnelAddress(spec.PeerTunnelAddr, spec.InterfaceName, spec.NetNS),
				}
				plannedDesired[item.InstanceID] = item
			}
		}
	}
	lastDesired := desiredByInstanceID(reconcile.Desired)
	actualSAs := saByInstanceID(reconcile.ActualSAs)
	fmt.Fprintf(w, "last_run: %s\n", formatUnixTime(reconcile.LastRunUnix))
	fmt.Fprintf(w, "desired_links: %d\n", reconcile.DesiredLinks)
	fmt.Fprintf(w, "planned_desired_links: %d\n", len(plannedDesired))
	fmt.Fprintf(w, "actual_sas: %d\n", len(reconcile.ActualSAs))
	fmt.Fprintf(w, "last_error: %s\n", dash(reconcile.LastError))
	ids := make([]string, 0, len(state.LinkInstances))
	for id := range state.LinkInstances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	fmt.Fprintf(w, "link_instances: %d\n", len(ids))
	for _, id := range ids {
		inst := state.LinkInstances[id]
		desired := lastDesired[id]
		if planned, ok := plannedDesired[id]; ok {
			desired = planned
		}
		sa := actualSAs[id]
		desiredHash := desired.DesiredSpecHash
		if desiredHash == "" {
			desiredHash = inst.DesiredSpecHash
		}
		fmt.Fprintf(w, "- id=%s group=%s peer=%s desired_hash=%s actual_hash=%s state=%s if=%s if_id=%d child_sa=%s local_tunnel=%s peer_tunnel=%s endpoint=%s sa=%s sa_local=%s sa_remote=%s sa_local_id=%s sa_remote_id=%s sa_reqid=%d owner=%s failures=%d backoff=%s error=%s\n",
			inst.ID,
			dash(inst.GroupID),
			inst.PeerZone,
			dash(shortHash(desiredHash)),
			dash(shortHash(inst.DesiredSpecHash)),
			dash(inst.ActualState),
			dash(inst.InterfaceName),
			inst.XFRMIfID,
			dash(inst.ChildSAName),
			dash(desired.LocalTunnelAddr),
			dash(desired.PeerTunnelAddr),
			dash(inst.Endpoint),
			formatSAState(sa),
			dash(sa.LocalEndpoint),
			dash(firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint)),
			dash(sa.LocalIdentity),
			dash(sa.RemoteIdentity),
			sa.ReqID,
			dash(inst.Owner.Manager),
			inst.FailureCount,
			formatUnixTime(inst.BackoffUntil),
			dash(inst.LastError),
		)
	}
	if len(ids) == 0 && len(plannedDesired) > 0 {
		plannedIDs := make([]string, 0, len(plannedDesired))
		for id := range plannedDesired {
			plannedIDs = append(plannedIDs, id)
		}
		sort.Strings(plannedIDs)
		for _, id := range plannedIDs {
			desired := plannedDesired[id]
			fmt.Fprintf(w, "- id=%s group=%s peer=%s desired_hash=%s actual_hash=- state=missing if=%s if_id=%d child_sa=- local_tunnel=%s peer_tunnel=%s endpoint=%s sa=- sa_endpoint=- owner=- failures=0 backoff=- error=-\n",
				desired.InstanceID,
				dash(desired.GroupID),
				desired.PeerZone,
				dash(shortHash(desired.DesiredSpecHash)),
				dash(desired.InterfaceName),
				desired.XFRMIfID,
				dash(desired.LocalTunnelAddr),
				dash(desired.PeerTunnelAddr),
				dash(desired.Endpoint),
			)
		}
	}
	fmt.Fprintf(w, "actions: %d\n", len(reconcile.Actions))
	for _, action := range reconcile.Actions {
		fmt.Fprintf(w, "- action=%s instance=%s group=%s peer=%s reason=%s\n",
			action.Action,
			dash(action.InstanceID),
			dash(action.GroupID),
			action.PeerZone,
			dash(action.Reason),
		)
	}
	fmt.Fprintf(w, "skipped: %d\n", len(reconcile.Skipped))
	for _, skip := range reconcile.Skipped {
		fmt.Fprintf(w, "- group=%s peer=%s reason=%s detail=%s\n",
			dash(skip.GroupID),
			skip.Peer,
			dash(skip.Reason),
			dash(skip.Detail),
		)
	}
	return nil
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

func saByInstanceID(items []linkSAState) map[string]linkSAState {
	out := map[string]linkSAState{}
	for _, item := range items {
		if item.Name != "" {
			out[item.Name] = item
		}
		if item.ChildSA != "" {
			out[item.ChildSA] = item
		}
	}
	return out
}

func formatSAState(sa linkSAState) string {
	if sa.Name == "" && sa.ChildSA == "" {
		return "-"
	}
	if sa.Established {
		return "established"
	}
	return "present"
}

func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}

func printDebugPeerDatagramStats(peerState syncPeerState) {
	stats := peerState.DatagramStats
	if stats == nil {
		stats = &datagramStats{}
	}
	fmt.Printf("datagram_too_large_dropped: %d\n", stats.TooLargeDropped)
	fmt.Printf("datagram_digest_only_announces: %d\n", stats.DigestOnlyAnnounces)
	fmt.Printf("datagram_chunk_fallbacks: %d\n", stats.ChunkFallbacks)
	if stats.LastTooLargeUnix == 0 {
		fmt.Printf("datagram_last_too_large: -\n")
		return
	}
	fmt.Printf("datagram_last_too_large: %s direction=%s object=%s zone=%s key=%s bytes=%d limit=%d\n",
		time.Unix(stats.LastTooLargeUnix, 0).UTC().Format(time.RFC3339),
		dash(stats.LastTooLargeDirection),
		dash(stats.LastTooLargeObject),
		dash(stats.LastTooLargeZone),
		dash(stats.LastTooLargeKey),
		stats.LastTooLargeBytes,
		stats.LastTooLargeLimit,
	)
}

func printDebugPeerObjectPullStats(peerState syncPeerState) {
	stats := peerState.ObjectPullStats
	if stats == nil {
		stats = &objectPullStats{}
	}
	fmt.Printf("object_pull_attempts: %d\n", stats.Attempts)
	fmt.Printf("object_pull_successes: %d\n", stats.Successes)
	fmt.Printf("object_pull_failures: %d\n", stats.Failures)
	fmt.Printf("object_pull_large_object_unreachable: %d\n", stats.LargeObjectUnreachable)
	if stats.LastUnix == 0 {
		fmt.Printf("object_pull_last: -\n")
		return
	}
	fmt.Printf("object_pull_last: %s object=%s zone=%s key=%s bytes=%d source_peer=%s unreachable=%t error=%s\n",
		time.Unix(stats.LastUnix, 0).UTC().Format(time.RFC3339),
		dash(stats.LastObject),
		dash(stats.LastZone),
		dash(stats.LastKey),
		stats.LastBytes,
		dash(stats.LastSourcePeer),
		stats.LastUnreachable,
		dash(stats.LastError),
	)
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
	configureValidation(state.Network)
	zs := state.Network.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	digest := zoneDigest(state.Network, path)
	verifyResult := "ok"
	if err := higgscrypto.VerifyChain(state.Network, path, rt.Now()); err != nil {
		verifyResult = err.Error()
	}
	revocation := state.Network.ActiveRevocation(path, rt.Now())
	fmt.Printf("zone: %s\n", path)
	fmt.Printf("root: %s\n", hex.EncodeToString(digest.RootHash))
	fmt.Printf("records: %d\n", len(zs.Records))
	fmt.Printf("history: %d\n", countHistory(zs))
	fmt.Printf("delegations: %d\n", len(zs.Delegations))
	fmt.Printf("revocations: %d\n", len(zs.Revocations))
	fmt.Printf("parent_proof: %d\n", len(zs.ParentProof))
	if revocation == nil {
		fmt.Printf("revoked: false\n")
	} else {
		fmt.Printf("revoked: true\n")
		fmt.Printf("revoked_by: %s\n", revocation.ParentZone)
		fmt.Printf("revoked_at: %s\n", formatUnixTime(revocation.RevokedAt))
		fmt.Printf("revocation_reason: %s\n", dash(revocation.Reason))
		fmt.Printf("revoked_authority_epoch: %d\n", revocation.RevokedAuthorityEpoch)
	}
	fmt.Printf("verify: %s\n", verifyResult)
	printDebugRecords("record", zs.Records)
	return nil
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

func printDebugRecords(prefix string, records map[string]*zone.Record) {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		record := records[key]
		if record == nil {
			continue
		}
		fmt.Printf("%s key=%s version=%d type=%s\n", prefix, key, record.Version, record.Type)
	}
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
	candidates, reflectorErr := collectSyncLocalEndpoints(port, config.AdvertiseAddrs, config.Reflectors, config.ReflectorTimeout, config.FilterPrivateIPv4)
	if reflectorErr != nil && len(gossip.ResolvePublicIPReflectors(config.Reflectors)) > 0 {
		fmt.Printf("reflector_error: %v\n", reflectorErr)
	}
	fmt.Printf("local_candidates: %d\n", len(candidates))
	for _, ep := range candidates {
		source := "unknown"
		switch ep.Source {
		case gossip.SourceAdvertise:
			source = "advertise"
		case gossip.SourceInterface:
			source = "interface"
		case gossip.SourceReflector:
			source = "reflector"
		}
		fmt.Printf("candidate addr=%s port=%d scope=%s priority=%d source=%s\n",
			ep.IP.String(), ep.Port, ep.Scope, ep.Priority, source)
	}

	discovered := gossip.ExtractPeerEndpoints(state.Network)
	fmt.Printf("discovered_peers: %d\n", len(discovered))
	for peerID, entries := range discovered {
		fmt.Printf("peer %s endpoints=%d\n", peerID, len(entries))
		for _, ep := range entries {
			fmt.Printf("  endpoint addr=%s port=%d scope=%s priority=%d protocol=%s source=%s last_observed=%s\n",
				ep.Address, ep.Port, ep.Scope, ep.Priority, ep.Protocol, dash(ep.Source), formatUnixTime(ep.LastObserved))
		}
	}
	return nil
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
