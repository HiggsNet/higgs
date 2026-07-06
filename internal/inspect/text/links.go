package text

import (
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/Catofes/higgs/internal/inspect"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func WriteLinksDebug(w io.Writer, view inspect.LinksDebugView) error {
	out := newLineWriter(w)
	inspection := view.Inspection
	inspection.Links = inspect.FilterLinkViews(inspection.Links, view.Filter)
	inspection.Actions = inspect.FilterLinkActions(inspection.Actions, view.Filter)
	inspection.Skipped = inspect.FilterLinkSkips(inspection.Skipped, view.Filter)
	out.LineIf(inspection.Summary.DesiredPlanError != "", "desired_plan_error: %s", inspection.Summary.DesiredPlanError)
	out.Linef("last_run: %s", formatUnixTime(inspection.Summary.LastRunUnix))
	out.Linef("desired_links: %d", inspection.Summary.DesiredLinks)
	out.Linef("planned_desired_links: %d", view.ReplannedDesired)
	out.LineIf(view.ReplanIgnored, "planned_desired_status: ignored_partial last_reconcile_desired=%d", view.LastDesiredLinks)
	out.Linef("desired_source: %s", dash(view.DesiredPlanSource))
	out.Linef("actual_sas: %d", inspection.Summary.ActualSAs)
	out.Linef("last_error: %s", dash(inspection.Summary.LastError))
	out.Linef("link_instances: %d", inspection.Summary.LinkInstances)
	if strings.TrimSpace(view.Filter) != "" {
		out.Linef("filter: %s", view.Filter)
		out.Linef("matched_links: %d", len(inspection.Links))
	}
	for _, link := range inspection.Links {
		spec, hasSpec := view.PlannedSpecs[link.ID]
		var specPtr *ipsec.TransportLinkSpec
		if hasSpec {
			specPtr = &spec
		}
		if link.Missing {
			writeDebugMissingLink(out, link, specPtr)
			continue
		}
		writeDebugLinkInstance(out, link, specPtr)
	}
	out.Linef("actions: %d", len(inspection.Actions))
	for _, action := range inspection.Actions {
		out.Linef("- action=%s instance=%s group=%s peer=%s reason=%s",
			action.Action,
			dash(action.InstanceID),
			dash(action.GroupID),
			action.PeerZone,
			dash(action.Reason),
		)
	}
	out.Linef("skipped: %d", len(inspection.Skipped))
	for _, skip := range inspection.Skipped {
		out.Linef("- group=%s peer=%s reason=%s detail=%s",
			dash(skip.GroupID),
			skip.Peer,
			dash(skip.Reason),
			dash(skip.Detail),
		)
	}
	return out.Err()
}

func writeDebugLinkInstance(out *lineWriter, link inspect.LinkView, spec *ipsec.TransportLinkSpec) {
	desired := inspect.DesiredLink{}
	if link.Desired != nil {
		desired = *link.Desired
	}
	sa := inspect.LinkSA{}
	if link.ActualSA != nil {
		sa = *link.ActualSA
	}
	out.Blank()
	out.Linef("link %s", link.ID)
	out.Linef("  peer: %s", link.PeerZone)
	out.Linef("  group: %s", dash(link.GroupID))
	out.Linef("  state: %s", dash(link.ActualState))
	out.Linef("  planner:")
	out.Linef("    link_id: %s", dash(firstNonEmpty(link.LinkID, desired.LinkID)))
	out.Linef("    path_key: %s", dash(firstNonEmpty(link.PathKey, desired.PathKey)))
	out.Linef("    runtime_id: %s", dash(firstNonEmpty(link.TransportID, desired.TransportID)))
	out.Linef("    desired_hash: %s", dash(shortTextHash(desired.DesiredSpecHash)))
	out.Linef("    actual_hash: %s", dash(shortTextHash(link.DesiredSpecHash)))
	out.Linef("    endpoint: %s", dash(link.Endpoint))
	out.Linef("    local_tunnel: %s", dash(link.LocalTunnelAddr))
	out.Linef("    peer_tunnel: %s", dash(link.PeerTunnelAddr))
	out.Linef("  xfrm:")
	out.Linef("    interface: %s", formatInterfaceWithIfID(link.InterfaceName, link.XFRMIfID))
	out.Linef("  strongswan:")
	out.Linef("    child_sa: %s", dash(firstNonEmpty(sa.ChildSA, link.ChildSAName, specChildSAName(spec))))
	out.Linef("    sa_state: %s", formatSAState(sa))
	out.Linef("    local_endpoint: %s", dash(sa.LocalEndpoint))
	out.Linef("    remote_endpoint: %s", dash(firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint)))
	out.Linef("    local_identity: %s", dash(sa.LocalIdentity))
	out.Linef("    remote_identity: %s", dash(sa.RemoteIdentity))
	out.Linef("    reqid: %s", formatUint32OrDash(sa.ReqID))
	out.Linef("    observed_interface: %s", formatDerivedInterfaceWithIfID(sa.XFRMIfID))
	writeDebugStrongSwanConfig(out, spec)
	out.Linef("  rotation:")
	out.Linef("    phase: %s", dash(link.Rotation.Phase))
	out.Linef("    port_generation select/runtime/staged: %s", debugPortGenerationSummary(spec, link.Rotation))
	out.Linef("    port local/remote/runtime/staged: %s", debugPortSummary(spec, link.Endpoint, firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint), link.Rotation.StagedGeneration))
	out.Linef("    staged_ike: %s", dash(link.Rotation.StagedIKEName))
	out.Linef("    staged_interface: %s", formatInterfaceWithIfID(link.Rotation.StagedInterfaceName, link.Rotation.StagedXFRMIfID))
	out.Linef("    deadline: %s", formatUnixTime(link.Rotation.RotateDeadline))
	out.Linef("  takeover:")
	out.Linef("    initiator_role: %s", dash(link.Takeover.InitiatorRole))
	out.Linef("    phase: %s", dash(link.Takeover.Phase))
	out.Linef("    until: %s", formatUnixTime(link.Takeover.Until))
	out.Linef("    observed_initiator: %s", dash(link.Takeover.ObservedInitiator))
	out.Linef("  health:")
	out.Linef("    owner: %s", dash(link.Owner.Manager))
	out.Linef("    failures: %d", link.FailureCount)
	out.Linef("    backoff_until: %s", formatUnixTime(link.BackoffUntil))
	out.Linef("    last_error: %s", dash(link.LastError))
	out.Linef("    takeover_error: %s", dash(link.Takeover.LastError))
	out.Linef("  routing:")
	out.Linef("    bird_state: %s", link.Routing.BirdState)
	out.Linef("    bird_neighbors: %s", link.Routing.BirdNeighbors)
	out.Linef("    bird_best_routes: %s", link.Routing.BirdBestRoutes)
}

func writeDebugMissingLink(out *lineWriter, link inspect.LinkView, spec *ipsec.TransportLinkSpec) {
	desired := inspect.DesiredLink{}
	if link.Desired != nil {
		desired = *link.Desired
	}
	out.Blank()
	out.Linef("link %s", link.ID)
	out.Linef("  peer: %s", link.PeerZone)
	out.Linef("  group: %s", dash(link.GroupID))
	out.Linef("  state: missing")
	out.Linef("  planner:")
	out.Linef("    desired_hash: %s", dash(shortTextHash(desired.DesiredSpecHash)))
	out.Linef("    actual_hash: -")
	out.Linef("    endpoint: %s", dash(desired.Endpoint))
	out.Linef("    local_tunnel: %s", dash(desired.LocalTunnelAddr))
	out.Linef("    peer_tunnel: %s", dash(desired.PeerTunnelAddr))
	out.Linef("  xfrm:")
	out.Linef("    interface: %s", formatInterfaceWithIfID(link.InterfaceName, link.XFRMIfID))
	out.Linef("  strongswan:")
	out.Linef("    child_sa: -")
	out.Linef("    sa_state: -")
	writeDebugStrongSwanConfig(out, spec)
	out.Linef("  health:")
	out.Linef("    owner: -")
	out.Linef("    failures: 0")
	out.Linef("    backoff_until: -")
	out.Linef("    last_error: -")
	out.Linef("  routing:")
	out.Linef("    bird_state: %s", link.Routing.BirdState)
	out.Linef("    bird_neighbors: %s", link.Routing.BirdNeighbors)
	out.Linef("    bird_best_routes: %s", link.Routing.BirdBestRoutes)
}

func specChildSAName(spec *ipsec.TransportLinkSpec) string {
	if spec == nil {
		return ""
	}
	return ipsec.ChildSAName(*spec)
}

func writeDebugStrongSwanConfig(out *lineWriter, spec *ipsec.TransportLinkSpec) {
	out.Linef("    config:")
	if spec == nil {
		out.Linef("      load_conn: -")
		return
	}
	conn, err := ipsec.BuildStrongSwanConnection(*spec)
	if err != nil {
		out.Linef("      load_conn_error: %s", err)
		return
	}
	childName := ipsec.ChildSAName(*spec)
	local, _ := conn["local"].(map[string]any)
	remote, _ := conn["remote"].(map[string]any)
	children, _ := conn["children"].(map[string]any)
	child, _ := children[childName].(map[string]any)
	out.Linef("      connection: %s", dash(spec.TransportID))
	out.Linef("      version: %s", dash(debugString(conn["version"])))
	out.Linef("      local_addrs: %s", debugStringList(conn["local_addrs"]))
	out.Linef("      remote_addrs: %s", debugStringList(conn["remote_addrs"]))
	out.Linef("      local_port: %s", dash(debugString(conn["local_port"])))
	out.Linef("      remote_port: %s", dash(debugString(conn["remote_port"])))
	out.Linef("      encap: %s", dash(debugString(conn["encap"])))
	out.Linef("      mobike: %s", dash(debugString(conn["mobike"])))
	out.Linef("      local_auth: %s", dash(debugString(local["auth"])))
	out.Linef("      local_id: %s", dash(debugString(local["id"])))
	out.Linef("      remote_auth: %s", dash(debugString(remote["auth"])))
	out.Linef("      remote_id: %s", dash(debugString(remote["id"])))
	out.Linef("      local_key_algorithm: %s", dash(spec.LocalPrivateKeyAlgorithm))
	out.Linef("      local_private_key: %s", presentOrDash(len(spec.LocalPrivateKey) > 0))
	out.Linef("      peer_public_key: %s", presentOrDash(len(spec.PeerPublicKey) > 0))
	out.Linef("      child: %s", dash(childName))
	out.Linef("      child_mode: %s", dash(debugString(child["mode"])))
	out.Linef("      child_start_action: %s", dash(debugString(child["start_action"])))
	out.Linef("      child_local_ts: %s", debugStringList(child["local_ts"]))
	out.Linef("      child_remote_ts: %s", debugStringList(child["remote_ts"]))
	out.Linef("      child_if_id_in: %s", formatDebugChildIfID(child["if_id_in"]))
	out.Linef("      child_if_id_out: %s", formatDebugChildIfID(child["if_id_out"]))
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
	return s
}

func debugString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}

func debugStringList(value any) string {
	switch v := value.(type) {
	case nil:
		return "-"
	case []string:
		if len(v) == 0 {
			return "-"
		}
		return strings.Join(v, ",")
	case []any:
		if len(v) == 0 {
			return "-"
		}
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, debugString(item))
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
		return ""
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
