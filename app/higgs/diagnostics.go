package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
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
	var birdInstances map[string]*BirdInstanceState
	if state != nil {
		birdInstances = state.BirdInstances
	}
	plannedDesired := map[string]desiredLinkState{}
	plannedSpecs := map[string]ipsec.TransportLinkSpec{}
	if rt != nil && rt.Config != nil && state != nil && state.Network != nil && !state.ManagedZone.IsRoot() && state.ManagedZone.Valid() && len(rt.Config.IPsec.LinkGroups) > 0 {
		plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, rt.Config.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: rt.Now()})
		if err != nil {
			fmt.Fprintf(w, "desired_plan_error: %s\n", err)
		} else {
			desired := injectIPsecKeyMaterial(state, plan.Desired)
			plan.Desired = desired
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
				plannedSpecs[item.InstanceID] = spec
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
		spec, hasSpec := plannedSpecs[id]
		sa := actualSAs[id]
		desiredHash := desired.DesiredSpecHash
		if desiredHash == "" {
			desiredHash = inst.DesiredSpecHash
		}
		var specPtr *ipsec.TransportLinkSpec
		if hasSpec {
			specPtr = &spec
		}
		printDebugLinkInstance(w, rt, state, birdInstances, inst, desired, sa, desiredHash, specPtr)
	}
	if len(ids) == 0 && len(plannedDesired) > 0 {
		plannedIDs := make([]string, 0, len(plannedDesired))
		for id := range plannedDesired {
			plannedIDs = append(plannedIDs, id)
		}
		sort.Strings(plannedIDs)
		for _, id := range plannedIDs {
			desired := plannedDesired[id]
			spec, hasSpec := plannedSpecs[id]
			var specPtr *ipsec.TransportLinkSpec
			if hasSpec {
				specPtr = &spec
			}
			printDebugMissingLink(w, rt, birdInstances, desired, specPtr)
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

func printDebugLinkInstance(w io.Writer, rt *Runtime, state *stateFile, birdInstances map[string]*BirdInstanceState, inst linkInstanceState, desired desiredLinkState, sa linkSAState, desiredHash string, spec *ipsec.TransportLinkSpec) {
	fmt.Fprintf(w, "\nlink %s\n", inst.ID)
	fmt.Fprintf(w, "  peer: %s\n", inst.PeerZone)
	fmt.Fprintf(w, "  group: %s\n", dash(inst.GroupID))
	fmt.Fprintf(w, "  state: %s\n", dash(inst.ActualState))
	fmt.Fprintf(w, "  planner:\n")
	fmt.Fprintf(w, "    desired_hash: %s\n", dash(shortHash(desiredHash)))
	fmt.Fprintf(w, "    actual_hash: %s\n", dash(shortHash(inst.DesiredSpecHash)))
	fmt.Fprintf(w, "    endpoint: %s\n", dash(firstNonEmpty(desired.Endpoint, inst.Endpoint)))
	fmt.Fprintf(w, "    local_tunnel: %s\n", dash(desired.LocalTunnelAddr))
	fmt.Fprintf(w, "    peer_tunnel: %s\n", dash(desired.PeerTunnelAddr))
	fmt.Fprintf(w, "  xfrm:\n")
	fmt.Fprintf(w, "    interface: %s\n", dash(inst.InterfaceName))
	fmt.Fprintf(w, "    if_id: %d\n", inst.XFRMIfID)
	fmt.Fprintf(w, "  strongswan:\n")
	fmt.Fprintf(w, "    child_sa: %s\n", dash(inst.ChildSAName))
	fmt.Fprintf(w, "    sa_state: %s\n", formatSAState(sa))
	fmt.Fprintf(w, "    local_endpoint: %s\n", dash(sa.LocalEndpoint))
	fmt.Fprintf(w, "    remote_endpoint: %s\n", dash(firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint)))
	fmt.Fprintf(w, "    local_identity: %s\n", dash(sa.LocalIdentity))
	fmt.Fprintf(w, "    remote_identity: %s\n", dash(sa.RemoteIdentity))
	fmt.Fprintf(w, "    reqid: %s\n", formatUint32OrDash(sa.ReqID))
	fmt.Fprintf(w, "    observed_if_id: %s\n", formatUint32OrDash(sa.XFRMIfID))
	printDebugStrongSwanConfig(w, spec)
	fmt.Fprintf(w, "  rotation:\n")
	fmt.Fprintf(w, "    phase: %s\n", dash(inst.RotatePhase))
	fmt.Fprintf(w, "    remote_generation: %d\n", inst.RemoteGeneration)
	fmt.Fprintf(w, "    staged_generation: %d\n", inst.StagedGeneration)
	fmt.Fprintf(w, "    staged_ike: %s\n", dash(inst.StagedIKEName))
	fmt.Fprintf(w, "    staged_interface: %s\n", dash(inst.StagedInterfaceName))
	fmt.Fprintf(w, "    staged_if_id: %s\n", formatUint32OrDash(inst.StagedXFRMIfID))
	fmt.Fprintf(w, "    deadline: %s\n", formatUnixTime(inst.RotateDeadline))
	fmt.Fprintf(w, "  takeover:\n")
	fmt.Fprintf(w, "    initiator_role: %s\n", dash(inst.InitiatorRole))
	fmt.Fprintf(w, "    phase: %s\n", dash(inst.TakeoverPhase))
	fmt.Fprintf(w, "    until: %s\n", formatUnixTime(inst.TakeoverUntil))
	fmt.Fprintf(w, "    observed_initiator: %s\n", dash(inst.ObservedInitiator))
	fmt.Fprintf(w, "  health:\n")
	fmt.Fprintf(w, "    owner: %s\n", dash(inst.Owner.Manager))
	fmt.Fprintf(w, "    failures: %d\n", inst.FailureCount)
	fmt.Fprintf(w, "    backoff_until: %s\n", formatUnixTime(inst.BackoffUntil))
	fmt.Fprintf(w, "    last_error: %s\n", dash(inst.LastError))
	fmt.Fprintf(w, "    takeover_error: %s\n", dash(inst.LastTakeoverError))
	fmt.Fprintf(w, "  routing:\n")
	birdState, neighborCount, bestRouteCount := debugLinkRoutingState(rt, birdInstances, inst.GroupID)
	fmt.Fprintf(w, "    bird_state: %s\n", birdState)
	fmt.Fprintf(w, "    bird_neighbors: %s\n", neighborCount)
	fmt.Fprintf(w, "    bird_best_routes: %s\n", bestRouteCount)
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

func linkGroupByID(groups []ipsec.LinkGroupSpec, id string) *ipsec.LinkGroupSpec {
	for i := range groups {
		if groups[i].ID == id {
			return &groups[i]
		}
	}
	return nil
}

func printDebugMissingLink(w io.Writer, rt *Runtime, birdInstances map[string]*BirdInstanceState, desired desiredLinkState, spec *ipsec.TransportLinkSpec) {
	fmt.Fprintf(w, "\nlink %s\n", desired.InstanceID)
	fmt.Fprintf(w, "  peer: %s\n", desired.PeerZone)
	fmt.Fprintf(w, "  group: %s\n", dash(desired.GroupID))
	fmt.Fprintf(w, "  state: missing\n")
	fmt.Fprintf(w, "  planner:\n")
	fmt.Fprintf(w, "    desired_hash: %s\n", dash(shortHash(desired.DesiredSpecHash)))
	fmt.Fprintf(w, "    actual_hash: -\n")
	fmt.Fprintf(w, "    endpoint: %s\n", dash(desired.Endpoint))
	fmt.Fprintf(w, "    local_tunnel: %s\n", dash(desired.LocalTunnelAddr))
	fmt.Fprintf(w, "    peer_tunnel: %s\n", dash(desired.PeerTunnelAddr))
	fmt.Fprintf(w, "  xfrm:\n")
	fmt.Fprintf(w, "    interface: %s\n", dash(desired.InterfaceName))
	fmt.Fprintf(w, "    if_id: %d\n", desired.XFRMIfID)
	fmt.Fprintf(w, "  strongswan:\n")
	fmt.Fprintf(w, "    child_sa: -\n")
	fmt.Fprintf(w, "    sa_state: -\n")
	printDebugStrongSwanConfig(w, spec)
	fmt.Fprintf(w, "  health:\n")
	fmt.Fprintf(w, "    owner: -\n")
	fmt.Fprintf(w, "    failures: 0\n")
	fmt.Fprintf(w, "    backoff_until: -\n")
	fmt.Fprintf(w, "    last_error: -\n")
	fmt.Fprintf(w, "  routing:\n")
	birdState, neighborCount, bestRouteCount := debugLinkRoutingState(rt, birdInstances, desired.GroupID)
	fmt.Fprintf(w, "    bird_state: %s\n", birdState)
	fmt.Fprintf(w, "    bird_neighbors: %s\n", neighborCount)
	fmt.Fprintf(w, "    bird_best_routes: %s\n", bestRouteCount)
}

func printDebugStrongSwanConfig(w io.Writer, spec *ipsec.TransportLinkSpec) {
	fmt.Fprintf(w, "    config:\n")
	if spec == nil {
		fmt.Fprintf(w, "      load_conn: -\n")
		return
	}
	conn, err := ipsec.BuildStrongSwanConnection(*spec)
	if err != nil {
		fmt.Fprintf(w, "      load_conn_error: %s\n", err)
		return
	}
	childName := ipsec.ChildSAName(*spec)
	local, _ := conn["local"].(map[string]any)
	remote, _ := conn["remote"].(map[string]any)
	children, _ := conn["children"].(map[string]any)
	child, _ := children[childName].(map[string]any)
	fmt.Fprintf(w, "      connection: %s\n", dash(spec.TransportID))
	fmt.Fprintf(w, "      version: %s\n", dash(debugString(conn["version"])))
	fmt.Fprintf(w, "      local_addrs: %s\n", debugStringList(conn["local_addrs"]))
	fmt.Fprintf(w, "      remote_addrs: %s\n", debugStringList(conn["remote_addrs"]))
	fmt.Fprintf(w, "      local_port: %s\n", dash(debugString(conn["local_port"])))
	fmt.Fprintf(w, "      remote_port: %s\n", dash(debugString(conn["remote_port"])))
	fmt.Fprintf(w, "      encap: %s\n", dash(debugString(conn["encap"])))
	fmt.Fprintf(w, "      mobike: %s\n", dash(debugString(conn["mobike"])))
	fmt.Fprintf(w, "      local_auth: %s\n", dash(debugString(local["auth"])))
	fmt.Fprintf(w, "      local_id: %s\n", dash(debugString(local["id"])))
	fmt.Fprintf(w, "      remote_auth: %s\n", dash(debugString(remote["auth"])))
	fmt.Fprintf(w, "      remote_id: %s\n", dash(debugString(remote["id"])))
	fmt.Fprintf(w, "      local_key_algorithm: %s\n", dash(spec.LocalPrivateKeyAlgorithm))
	fmt.Fprintf(w, "      local_private_key: %s\n", presentOrDash(len(spec.LocalPrivateKey) > 0))
	fmt.Fprintf(w, "      peer_public_key: %s\n", presentOrDash(len(spec.PeerPublicKey) > 0))
	fmt.Fprintf(w, "      child: %s\n", dash(childName))
	fmt.Fprintf(w, "      child_mode: %s\n", dash(debugString(child["mode"])))
	fmt.Fprintf(w, "      child_start_action: %s\n", dash(debugString(child["start_action"])))
	fmt.Fprintf(w, "      child_local_ts: %s\n", debugStringList(child["local_ts"]))
	fmt.Fprintf(w, "      child_remote_ts: %s\n", debugStringList(child["remote_ts"]))
	fmt.Fprintf(w, "      child_if_id_in: %s\n", dash(debugString(child["if_id_in"])))
	fmt.Fprintf(w, "      child_if_id_out: %s\n", dash(debugString(child["if_id_out"])))
}

func debugString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func debugStringList(value any) string {
	switch v := value.(type) {
	case []string:
		if len(v) == 0 {
			return "-"
		}
		return strings.Join(v, ",")
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, debugString(item))
		}
		if len(parts) == 0 {
			return "-"
		}
		return strings.Join(parts, ",")
	default:
		s := debugString(value)
		if s == "" {
			return "-"
		}
		return s
	}
}

func presentOrDash(ok bool) string {
	if ok {
		return "present"
	}
	return "-"
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
	if sa.ChildState != "" {
		return strings.ToLower(sa.ChildState)
	}
	if sa.IKEState != "" {
		return strings.ToLower(sa.IKEState)
	}
	return "present"
}

func formatUint32OrDash(value uint32) string {
	if value == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", value)
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
	fmt.Printf("catalog_root: %s\n", dash(stats.LastCatalogRootHex))
	fmt.Printf("catalog_zone_count: %d\n", stats.LastCatalogZoneCount)
	fmt.Printf("catalog_last_page_cursor: %s\n", dash(stats.LastCatalogCursor))
	fmt.Printf("catalog_last_page_entries: %d\n", stats.LastCatalogPageEntries)
	fmt.Printf("catalog_last_rejected_reason: %s\n", dash(stats.LastCatalogRejectedReason))
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
	paths := make([]zone.ZonePath, 0, len(state.Network.Zones))
	if path.Valid() {
		if state.Network.Zones[path] == nil {
			return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
		}
		paths = append(paths, path)
	} else {
		for p := range state.Network.Zones {
			paths = append(paths, p)
		}
		sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	}
	total := 0
	for _, p := range paths {
		total += countRecordsWithPrefix(state.Network.Zones[p].Records, prefix)
	}
	fmt.Fprintf(w, "zones: %d\n", len(paths))
	fmt.Fprintf(w, "records: %d\n", total)
	if prefix != "" {
		fmt.Fprintf(w, "prefix: %s\n", prefix)
	}
	for _, p := range paths {
		zs := state.Network.Zones[p]
		if zs == nil {
			continue
		}
		keys := make([]string, 0, len(zs.Records))
		for key := range zs.Records {
			if prefix == "" || strings.HasPrefix(key, prefix) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		fmt.Fprintf(w, "\nzone %s\n", p)
		fmt.Fprintf(w, "  records: %d\n", len(keys))
		for _, key := range keys {
			record := zs.Records[key]
			if record == nil {
				continue
			}
			fmt.Fprintf(w, "  record key=%s version=%d type=%s signed_by=%s timestamp=%s hash=%s\n",
				key,
				record.Version,
				dash(record.Type),
				shortKey(record.SignedBy),
				formatUnixTime(record.Timestamp),
				shortBytes(higgscrypto.RecordHash(record)),
			)
			if values {
				fmt.Fprintf(w, "    value: %s\n", formatDebugRecordValue(record.Value))
			}
		}
	}
	return nil
}

func countRecordsWithPrefix(records map[string]*zone.Record, prefix string) int {
	count := 0
	for key, record := range records {
		if record == nil {
			continue
		}
		if prefix == "" || strings.HasPrefix(key, prefix) {
			count++
		}
	}
	return count
}

func formatDebugRecordValue(value []byte) string {
	var decoded any
	if err := json.Unmarshal(value, &decoded); err == nil {
		if data, err := json.Marshal(decoded); err == nil {
			return string(data)
		}
	}
	return string(value)
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
	advertiseAddrs, reflectors := filterEndpointDiscoveryInputs(config, port)
	candidates, reflectorErr := collectSyncLocalEndpoints(port, advertiseAddrs, reflectors, config.ReflectorTimeout, config.FilterPrivateIPv4)
	if reflectorErr != nil && len(gossip.ResolvePublicIPReflectors(reflectors)) > 0 {
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
			writeAdmissionDiagnosis(os.Stdout, *response.Admission)
			return nil
		}
		fmt.Printf("admission: not available from daemon\n")
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	diagnosis := diagnoseAutoJoinAdmission(state, rt.Now())
	writeAdmissionDiagnosis(os.Stdout, diagnosis)
	return nil
}

func writeAdmissionDiagnosis(w io.Writer, d admissionDiagnosis) {
	fmt.Fprintf(w, "managed_zone: %s\n", d.ManagedZone)
	fmt.Fprintf(w, "parent_zone: %s\n", d.ParentZone)
	fmt.Fprintf(w, "pending: %t\n", d.Pending)
	fmt.Fprintf(w, "reason: %s\n", dash(d.Reason))
	if d.ReasonDetail != "" {
		fmt.Fprintf(w, "reason_detail: %s\n", d.ReasonDetail)
	}
	fmt.Fprintf(w, "has_zone_private_key: %t\n", d.HasZonePrivateKey)
	fmt.Fprintf(w, "parent_zone_known: %t\n", d.ParentZoneKnown)
	fmt.Fprintf(w, "parent_authority_known: %t\n", d.ParentAuthorityKnown)
	fmt.Fprintf(w, "delegation_known: %t\n", d.DelegationKnown)
	fmt.Fprintf(w, "delegation_key_matches: %t\n", d.DelegationKeyMatches)
	fmt.Fprintf(w, "pending_since: %s\n", formatUnixTime(d.PendingSinceUnix))
	fmt.Fprintf(w, "adopted_at: %s\n", formatUnixTime(d.AdoptedAtUnix))
	fmt.Fprintf(w, "last_bootstrap_sync: %s\n", formatUnixTime(d.LastBootstrapSyncUnix))
	if d.LastAdoptionError != "" {
		fmt.Fprintf(w, "last_adoption_error: %s\n", d.LastAdoptionError)
	}
	if d.JoinRequestB64 != "" {
		fmt.Fprintf(w, "join_request: %s\n", d.JoinRequestB64)
		fmt.Fprintf(w, "join_hint: %s\n", "higgs delegate issue <join_request> (on parent zone admin)")
	}
	fmt.Fprintf(w, "boundary: auto-join only completes identity materialization; TransportLink presence depends on local overlay/link group config, peer ipsec/* records, peer MeshPolicy and provider apply state\n")
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
