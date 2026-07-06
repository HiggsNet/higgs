package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
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
	endpoints := inspectPeerEndpoints(peerID, peerState, config, state.Network, now)
	resolved := "-"
	if addr := known[peerID]; addr != nil {
		resolved = addr.String()
	}
	if selected := selectedPeerEndpointAddr(endpoints); selected != "" {
		resolved = selected
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
	printDebugPeerSyncFlow(peerState)
	printDebugPeerDatagramStats(peerState)
	printDebugPeerObjectPullStats(peerState)
	return nil
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
	view := build.Inspection
	view.Links = filterLinkViews(view.Links, filter)
	view.Actions = filterLinkActions(view.Actions, filter)
	view.Skipped = filterLinkSkips(view.Skipped, filter)
	if view.Summary.DesiredPlanError != "" {
		fmt.Fprintf(w, "desired_plan_error: %s\n", view.Summary.DesiredPlanError)
	}
	fmt.Fprintf(w, "last_run: %s\n", formatUnixTime(view.Summary.LastRunUnix))
	fmt.Fprintf(w, "desired_links: %d\n", view.Summary.DesiredLinks)
	fmt.Fprintf(w, "planned_desired_links: %d\n", build.ReplannedDesired)
	if build.ReplanIgnored {
		fmt.Fprintf(w, "planned_desired_status: ignored_partial last_reconcile_desired=%d\n", build.LastDesiredLinks)
	}
	fmt.Fprintf(w, "desired_source: %s\n", dash(build.DesiredPlanSource))
	fmt.Fprintf(w, "actual_sas: %d\n", view.Summary.ActualSAs)
	fmt.Fprintf(w, "last_error: %s\n", dash(view.Summary.LastError))
	fmt.Fprintf(w, "link_instances: %d\n", view.Summary.LinkInstances)
	if strings.TrimSpace(filter) != "" {
		fmt.Fprintf(w, "filter: %s\n", filter)
		fmt.Fprintf(w, "matched_links: %d\n", len(view.Links))
	}
	for _, link := range view.Links {
		spec, hasSpec := build.PlannedSpecs[link.ID]
		var specPtr *ipsec.TransportLinkSpec
		if hasSpec {
			specPtr = &spec
		}
		if link.Missing {
			printDebugMissingLink(w, link, specPtr)
			continue
		}
		printDebugLinkInstance(w, link, specPtr)
	}
	fmt.Fprintf(w, "actions: %d\n", len(view.Actions))
	for _, action := range view.Actions {
		fmt.Fprintf(w, "- action=%s instance=%s group=%s peer=%s reason=%s\n",
			action.Action,
			dash(action.InstanceID),
			dash(action.GroupID),
			action.PeerZone,
			dash(action.Reason),
		)
	}
	fmt.Fprintf(w, "skipped: %d\n", len(view.Skipped))
	for _, skip := range view.Skipped {
		fmt.Fprintf(w, "- group=%s peer=%s reason=%s detail=%s\n",
			dash(skip.GroupID),
			skip.Peer,
			dash(skip.Reason),
			dash(skip.Detail),
		)
	}
	return nil
}

func filterLinkViews(links []inspect.LinkView, filter string) []inspect.LinkView {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" {
		return links
	}
	out := make([]inspect.LinkView, 0, len(links))
	for _, link := range links {
		if linkMatchesFilter(link, filter) {
			out = append(out, link)
		}
	}
	return out
}

func filterLinkActions(actions []inspect.LinkAction, filter string) []inspect.LinkAction {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" {
		return actions
	}
	out := make([]inspect.LinkAction, 0, len(actions))
	for _, action := range actions {
		if stringMatchesFilter(filter, action.InstanceID, action.GroupID, action.PeerZone, action.Action, action.Reason) {
			out = append(out, action)
		}
	}
	return out
}

func filterLinkSkips(skips []inspect.LinkSkip, filter string) []inspect.LinkSkip {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" {
		return skips
	}
	out := make([]inspect.LinkSkip, 0, len(skips))
	for _, skip := range skips {
		if stringMatchesFilter(filter, skip.GroupID, skip.Peer, skip.Reason, skip.Detail) {
			out = append(out, skip)
		}
	}
	return out
}

func linkMatchesFilter(link inspect.LinkView, filter string) bool {
	values := []string{
		link.ID,
		link.PeerZone,
		link.GroupID,
		link.TransportKind,
		link.LinkID,
		link.PathKey,
		link.TransportID,
		link.Endpoint,
		link.InterfaceName,
		link.ChildSAName,
		link.Rotation.Phase,
		link.Rotation.StagedIKEName,
		link.Rotation.StagedChildSAName,
		link.Rotation.StagedInterfaceName,
		link.Takeover.InitiatorRole,
		link.Takeover.ObservedInitiator,
	}
	if link.Desired != nil {
		values = append(values,
			link.Desired.InstanceID,
			link.Desired.PeerZone,
			link.Desired.GroupID,
			link.Desired.LinkID,
			link.Desired.PathKey,
			link.Desired.TransportID,
			link.Desired.InterfaceName,
			link.Desired.Endpoint,
		)
	}
	if link.ActualSA != nil {
		values = append(values,
			link.ActualSA.Name,
			link.ActualSA.Peer,
			link.ActualSA.ChildSA,
			link.ActualSA.LocalIdentity,
			link.ActualSA.RemoteIdentity,
			link.ActualSA.LocalEndpoint,
			link.ActualSA.RemoteEndpoint,
			link.ActualSA.Endpoint,
		)
	}
	if link.Health != nil {
		values = append(values, link.Health.InstanceID, link.Health.ProbeID, link.Health.InterfaceName, link.Health.State)
	}
	return stringMatchesFilter(filter, values...)
}

func stringMatchesFilter(filter string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), filter) {
			return true
		}
	}
	return false
}

func printDebugLinkInstance(w io.Writer, link inspect.LinkView, spec *ipsec.TransportLinkSpec) {
	desired := inspect.DesiredLink{}
	if link.Desired != nil {
		desired = *link.Desired
	}
	sa := inspect.LinkSA{}
	if link.ActualSA != nil {
		sa = *link.ActualSA
	}
	fmt.Fprintf(w, "\nlink %s\n", link.ID)
	fmt.Fprintf(w, "  peer: %s\n", link.PeerZone)
	fmt.Fprintf(w, "  group: %s\n", dash(link.GroupID))
	fmt.Fprintf(w, "  state: %s\n", dash(link.ActualState))
	fmt.Fprintf(w, "  planner:\n")
	fmt.Fprintf(w, "    link_id: %s\n", dash(firstNonEmpty(link.LinkID, desired.LinkID)))
	fmt.Fprintf(w, "    path_key: %s\n", dash(firstNonEmpty(link.PathKey, desired.PathKey)))
	fmt.Fprintf(w, "    runtime_id: %s\n", dash(firstNonEmpty(link.TransportID, desired.TransportID)))
	fmt.Fprintf(w, "    desired_hash: %s\n", dash(shortHash(desired.DesiredSpecHash)))
	fmt.Fprintf(w, "    actual_hash: %s\n", dash(shortHash(link.DesiredSpecHash)))
	fmt.Fprintf(w, "    endpoint: %s\n", dash(link.Endpoint))
	fmt.Fprintf(w, "    local_tunnel: %s\n", dash(link.LocalTunnelAddr))
	fmt.Fprintf(w, "    peer_tunnel: %s\n", dash(link.PeerTunnelAddr))
	fmt.Fprintf(w, "  xfrm:\n")
	fmt.Fprintf(w, "    interface: %s\n", formatInterfaceWithIfID(link.InterfaceName, link.XFRMIfID))
	fmt.Fprintf(w, "  strongswan:\n")
	fmt.Fprintf(w, "    child_sa: %s\n", dash(firstNonEmpty(sa.ChildSA, link.ChildSAName, specChildSAName(spec))))
	fmt.Fprintf(w, "    sa_state: %s\n", formatSAState(sa))
	fmt.Fprintf(w, "    local_endpoint: %s\n", dash(sa.LocalEndpoint))
	fmt.Fprintf(w, "    remote_endpoint: %s\n", dash(firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint)))
	fmt.Fprintf(w, "    local_identity: %s\n", dash(sa.LocalIdentity))
	fmt.Fprintf(w, "    remote_identity: %s\n", dash(sa.RemoteIdentity))
	fmt.Fprintf(w, "    reqid: %s\n", formatUint32OrDash(sa.ReqID))
	fmt.Fprintf(w, "    observed_interface: %s\n", formatDerivedInterfaceWithIfID(sa.XFRMIfID))
	printDebugStrongSwanConfig(w, spec)
	fmt.Fprintf(w, "  rotation:\n")
	fmt.Fprintf(w, "    phase: %s\n", dash(link.Rotation.Phase))
	fmt.Fprintf(w, "    port_generation select/runtime/staged: %s\n", debugPortGenerationSummary(spec, link.Rotation))
	fmt.Fprintf(w, "    port local/remote/runtime/staged: %s\n", debugPortSummary(spec, link.Endpoint, firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint), link.Rotation.StagedGeneration))
	fmt.Fprintf(w, "    staged_ike: %s\n", dash(link.Rotation.StagedIKEName))
	fmt.Fprintf(w, "    staged_interface: %s\n", formatInterfaceWithIfID(link.Rotation.StagedInterfaceName, link.Rotation.StagedXFRMIfID))
	fmt.Fprintf(w, "    deadline: %s\n", formatUnixTime(link.Rotation.RotateDeadline))
	fmt.Fprintf(w, "  takeover:\n")
	fmt.Fprintf(w, "    initiator_role: %s\n", dash(link.Takeover.InitiatorRole))
	fmt.Fprintf(w, "    phase: %s\n", dash(link.Takeover.Phase))
	fmt.Fprintf(w, "    until: %s\n", formatUnixTime(link.Takeover.Until))
	fmt.Fprintf(w, "    observed_initiator: %s\n", dash(link.Takeover.ObservedInitiator))
	fmt.Fprintf(w, "  health:\n")
	fmt.Fprintf(w, "    owner: %s\n", dash(link.Owner.Manager))
	fmt.Fprintf(w, "    failures: %d\n", link.FailureCount)
	fmt.Fprintf(w, "    backoff_until: %s\n", formatUnixTime(link.BackoffUntil))
	fmt.Fprintf(w, "    last_error: %s\n", dash(link.LastError))
	fmt.Fprintf(w, "    takeover_error: %s\n", dash(link.Takeover.LastError))
	fmt.Fprintf(w, "  routing:\n")
	fmt.Fprintf(w, "    bird_state: %s\n", link.Routing.BirdState)
	fmt.Fprintf(w, "    bird_neighbors: %s\n", link.Routing.BirdNeighbors)
	fmt.Fprintf(w, "    bird_best_routes: %s\n", link.Routing.BirdBestRoutes)
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

func printDebugMissingLink(w io.Writer, link inspect.LinkView, spec *ipsec.TransportLinkSpec) {
	desired := inspect.DesiredLink{}
	if link.Desired != nil {
		desired = *link.Desired
	}
	fmt.Fprintf(w, "\nlink %s\n", link.ID)
	fmt.Fprintf(w, "  peer: %s\n", link.PeerZone)
	fmt.Fprintf(w, "  group: %s\n", dash(link.GroupID))
	fmt.Fprintf(w, "  state: missing\n")
	fmt.Fprintf(w, "  planner:\n")
	fmt.Fprintf(w, "    desired_hash: %s\n", dash(shortHash(desired.DesiredSpecHash)))
	fmt.Fprintf(w, "    actual_hash: -\n")
	fmt.Fprintf(w, "    endpoint: %s\n", dash(desired.Endpoint))
	fmt.Fprintf(w, "    local_tunnel: %s\n", dash(desired.LocalTunnelAddr))
	fmt.Fprintf(w, "    peer_tunnel: %s\n", dash(desired.PeerTunnelAddr))
	fmt.Fprintf(w, "  xfrm:\n")
	fmt.Fprintf(w, "    interface: %s\n", formatInterfaceWithIfID(link.InterfaceName, link.XFRMIfID))
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
	fmt.Fprintf(w, "    bird_state: %s\n", link.Routing.BirdState)
	fmt.Fprintf(w, "    bird_neighbors: %s\n", link.Routing.BirdNeighbors)
	fmt.Fprintf(w, "    bird_best_routes: %s\n", link.Routing.BirdBestRoutes)
}

func specChildSAName(spec *ipsec.TransportLinkSpec) string {
	if spec == nil {
		return ""
	}
	return ipsec.ChildSAName(*spec)
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
	fmt.Fprintf(w, "      child_if_id_in: %s\n", formatDebugChildIfID(child["if_id_in"]))
	fmt.Fprintf(w, "      child_if_id_out: %s\n", formatDebugChildIfID(child["if_id_out"]))
}

func formatInterfaceWithIfID(name string, ifID uint32) string {
	if name == "" && ifID == 0 {
		return "-"
	}
	if name == "" {
		name = ipsec.StableInterfaceName(ifID)
	}
	if ifID == 0 {
		return dash(name)
	}
	return fmt.Sprintf("%s(%d)", name, ifID)
}

func formatDerivedInterfaceWithIfID(ifID uint32) string {
	if ifID == 0 {
		return "-"
	}
	return formatInterfaceWithIfID(ipsec.StableInterfaceName(ifID), ifID)
}

func formatDebugChildIfID(value any) string {
	s := debugString(value)
	if s == "" {
		return "-"
	}
	var id uint32
	if _, err := fmt.Sscanf(s, "%d", &id); err == nil && id != 0 {
		return formatDerivedInterfaceWithIfID(id)
	}
	return dash(s)
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

func formatSAState(sa inspect.LinkSA) string {
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

func debugPortGenerationSummary(spec *ipsec.TransportLinkSpec, rotation inspect.LinkRotation) string {
	return fmt.Sprintf("%s/%d/%d", debugSelectedGeneration(spec), rotation.RemoteGeneration, rotation.StagedGeneration)
}

func debugPortSummary(spec *ipsec.TransportLinkSpec, selectedEndpoint, runtimeEndpoint string, stagedGeneration uint64) string {
	return fmt.Sprintf("%s/%s/%s/%s",
		dash(debugLocalPort(spec)),
		dash(debugRemotePort(spec, selectedEndpoint)),
		dash(debugEndpointPort(runtimeEndpoint)),
		dash(debugStagedPort(spec, stagedGeneration)),
	)
}

func debugSelectedGeneration(spec *ipsec.TransportLinkSpec) string {
	if spec == nil {
		return "-"
	}
	return fmt.Sprintf("%d", spec.Generation)
}

func debugLocalPort(spec *ipsec.TransportLinkSpec) string {
	if spec == nil {
		return ""
	}
	if spec.LocalIKEPort != 0 {
		return fmt.Sprintf("%d", spec.LocalIKEPort)
	}
	return fmt.Sprintf("%d", ipsec.DefaultNATTPort)
}

func debugRemotePort(spec *ipsec.TransportLinkSpec, endpoint string) string {
	if spec != nil {
		if point, ok := firstContactPointForDebug(spec.ContactPoints); ok {
			return debugContactPort(point)
		}
	}
	return debugEndpointPort(endpoint)
}

func debugStagedPort(spec *ipsec.TransportLinkSpec, stagedGeneration uint64) string {
	if spec == nil || stagedGeneration == 0 {
		return ""
	}
	for _, point := range spec.ContactPoints {
		if point.Generation == stagedGeneration {
			return debugContactPort(point)
		}
	}
	return ""
}

func debugContactPort(point ipsec.ContactPoint) string {
	if point.NATTPort != 0 {
		return fmt.Sprintf("%d", point.NATTPort)
	}
	if point.IKEPort != 0 {
		return fmt.Sprintf("%d", point.IKEPort)
	}
	return ""
}

func debugEndpointPort(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ""
	}
	return port
}

func firstContactPointForDebug(points []ipsec.ContactPoint) (ipsec.ContactPoint, bool) {
	for _, point := range points {
		return point, true
	}
	return ipsec.ContactPoint{}, false
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

func printDebugPeerSyncFlow(peerState syncPeerState) {
	fmt.Printf("active_pull_state: %s\n", dash(peerState.ActivePullState))
	fmt.Printf("active_pull_last_event: %s\n", dash(peerState.ActivePullLastEvent))
	fmt.Printf("active_pull_updated: %s\n", formatUnixTime(peerState.ActivePullUpdatedUnix))
	fmt.Printf("hint_accepted: %d\n", peerState.HintAccepted)
	fmt.Printf("hint_suppressed: %d\n", peerState.HintSuppressed)
	fmt.Printf("hint_last: %s reason=%s suppression=%s\n",
		formatUnixTime(peerState.LastHintUnix),
		dash(peerState.LastHintReason),
		dash(peerState.LastHintSuppression),
	)
	fmt.Printf("read_only_responder: %d\n", peerState.ReadOnlyResponder)
	fmt.Printf("read_only_responder_last: %s kind=%s zone=%s\n",
		formatUnixTime(peerState.LastResponderUnix),
		dash(peerState.LastResponderKind),
		dash(peerState.LastResponderZone),
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
	var activeRevocation *inspect.RevocationView
	if revocation != nil {
		view := inspect.BuildRevocation(revocation)
		activeRevocation = &view
	}
	return inspecttext.WriteZoneDebug(os.Stdout, inspecttext.ZoneDebugView{
		Detail: inspect.BuildZoneDetail(inspect.ZoneDetailInput{
			Path:           path,
			State:          zs,
			Network:        state.Network,
			Now:            rt.Now(),
			IncludeHistory: false,
		}),
		RootHash:         hex.EncodeToString(digest.RootHash),
		VerifyResult:     verifyResult,
		ActiveRevocation: activeRevocation,
	})
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
