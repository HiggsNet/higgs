package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
	inspecttext "github.com/Catofes/higgs/internal/inspect/text"
	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

type manualPortRotateResult struct {
	Zone               zone.ZonePath `json:"zone"`
	PreviousGeneration uint64        `json:"previous_generation,omitempty"`
	CurrentGeneration  uint64        `json:"current_generation"`
	PreviousIKE        uint16        `json:"previous_ike,omitempty"`
	PreviousNATT       uint16        `json:"previous_natt,omitempty"`
	CurrentIKE         uint16        `json:"current_ike"`
	CurrentNATT        uint16        `json:"current_natt"`
	PreviousValidUntil int64         `json:"previous_valid_until,omitempty"`
}

func debugRotatePort(direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if !direct {
		result, ok, err := rotateIPsecPortViaControl(rt)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("daemon control socket unavailable; start the daemon to trigger firewall/IPsec reconcile, or rerun with --direct to write the local DB only")
		}
		printManualPortRotateResult("daemon", result)
		return nil
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	result, err := forceLocalIPsecPortRotate(rt.Config, state, rt.Now())
	if err != nil {
		return err
	}
	if err := rt.SaveState(state); err != nil {
		return err
	}
	printManualPortRotateResult("direct", result)
	return nil
}

func debugRotate(ctx context.Context, filter string) error {
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
		build := linkInspectionBuildFromControl(response.Links)
		storedSAs := append([]linkSAState(nil), response.Links.ActualSAs...)
		return writeDebugRotateFromBuild(os.Stdout, build, filter, storedSAs, nil, nil, "daemon_sas", "direct_live_sas")
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	var liveSAs []linkSAState
	var liveErr error
	if rt.Config != nil && rt.Config.IPsec.Driver != ipsecDriverDryRun {
		drivers, err := newIPsecCleanupDrivers(rt.Config)
		if err != nil {
			liveErr = err
		} else {
			if drivers.close != nil {
				defer drivers.close()
			}
			if drivers.ipsecDriver != nil {
				sas, err := drivers.ipsecDriver.ListSAs(ctx)
				if err != nil {
					liveErr = err
				} else {
					liveSAs = linkSAStatesFromIPsecSAs(sas)
				}
			}
		}
	}
	return writeDebugRotate(os.Stdout, rt, state, filter, liveSAs, liveErr)
}

func writeDebugRotate(w io.Writer, rt *Runtime, state *stateFile, filter string, liveSAs []linkSAState, liveErr error) error {
	build := buildLinkInspection(rt, state, nil)
	storedSAs := []linkSAState(nil)
	if state != nil && state.IPsecReconcile != nil {
		storedSAs = state.IPsecReconcile.ActualSAs
	}
	return writeDebugRotateFromBuild(w, build, filter, storedSAs, liveSAs, liveErr, "stored_sas", "live_sas")
}

func writeDebugRotateFromBuild(w io.Writer, build linkInspectionBuild, filter string, storedSAs, liveSAs []linkSAState, liveErr error, storedLabel, liveLabel string) error {
	links := filterLinkViews(build.Inspection.Links, filter)
	view := inspect.RotateDebugView{
		LastRunUnix:       build.Inspection.Summary.LastRunUnix,
		LinkInstances:     build.Inspection.Summary.LinkInstances,
		PlannedDesired:    build.ReplannedDesired,
		ReplanIgnored:     build.ReplanIgnored,
		LastDesiredLinks:  build.LastDesiredLinks,
		DesiredPlanSource: build.DesiredPlanSource,
		Filter:            strings.TrimSpace(filter),
		StoredLabel:       storedLabel,
		LiveLabel:         liveLabel,
		StoredSACount:     len(storedSAs),
		LiveSACount:       len(liveSAs),
	}
	if liveErr != nil {
		view.LiveSAError = liveErr.Error()
	}
	for _, link := range links {
		spec, hasSpec := build.PlannedSpecs[link.ID]
		var specPtr *ipsec.TransportLinkSpec
		if hasSpec {
			specPtr = &spec
		}
		staged := rotateRuntimeStaged(link, specPtr, append(storedSAs, liveSAs...))
		view.Links = append(view.Links, inspect.RotateDebugLink{
			Link:                  link,
			PortGenerationSummary: debugPortGenerationSummary(specPtr, link.Rotation),
			PortSummary:           debugPortSummary(specPtr, link.Endpoint, link.Endpoint, link.Rotation.StagedGeneration),
			Current:               rotateRuntimeCurrent(link, specPtr),
			Staged:                staged,
			HasStaged:             !rotateRuntimeEmpty(staged),
			StoredMatchingSAs:     inspectLinkSAs(matchingRotateSAs(link, storedSAs)),
			LiveMatchingSAs:       inspectLinkSAs(matchingRotateSAs(link, liveSAs)),
		})
	}
	return inspecttext.WriteRotateDebug(w, view)
}

type rotateRuntimeView = inspect.RotateRuntimeView

func rotateRuntimeEmpty(v rotateRuntimeView) bool {
	return v.RuntimeID == "" && v.ChildSAName == "" && v.InterfaceName == "" && v.XFRMIfID == 0 && v.State == ""
}

func rotateRuntimeCurrent(link inspect.LinkView, spec *ipsec.TransportLinkSpec) rotateRuntimeView {
	out := rotateRuntimeView{
		State:           "expected_current",
		Generation:      link.Rotation.RemoteGeneration,
		Port:            debugEndpointPort(link.Endpoint),
		RuntimeID:       link.TransportID,
		ChildSAName:     link.ChildSAName,
		InterfaceName:   link.InterfaceName,
		XFRMIfID:        link.XFRMIfID,
		Endpoint:        link.Endpoint,
		LocalTunnelAddr: link.LocalTunnelAddr,
		PeerTunnelAddr:  link.PeerTunnelAddr,
	}
	if link.Desired != nil {
		out.RuntimeID = firstNonEmpty(out.RuntimeID, link.Desired.TransportID)
		out.InterfaceName = firstNonEmpty(out.InterfaceName, link.Desired.InterfaceName)
		out.XFRMIfID = firstNonZeroUint32(out.XFRMIfID, link.Desired.XFRMIfID)
		out.Endpoint = firstNonEmpty(out.Endpoint, link.Desired.Endpoint)
		out.Port = firstNonEmpty(out.Port, debugEndpointPort(link.Desired.Endpoint))
		if rotateRuntimeMatchesDesired(out, *link.Desired) {
			out.LocalTunnelAddr = firstNonEmpty(out.LocalTunnelAddr, link.Desired.LocalTunnelAddr)
			out.PeerTunnelAddr = firstNonEmpty(out.PeerTunnelAddr, link.Desired.PeerTunnelAddr)
		}
	}
	if spec != nil {
		out.Generation = firstNonZeroUint64(out.Generation, spec.Generation)
		out.Port = firstNonEmpty(out.Port, debugRemotePort(spec, ""))
		out.RuntimeID = firstNonEmpty(out.RuntimeID, spec.TransportID)
		out.ChildSAName = firstNonEmpty(out.ChildSAName, ipsec.ChildSAName(*spec))
		out.InterfaceName = firstNonEmpty(out.InterfaceName, spec.InterfaceName)
		out.XFRMIfID = firstNonZeroUint32(out.XFRMIfID, spec.XFRMIfID)
		out.Endpoint = firstNonEmpty(out.Endpoint, summarizeContactEndpoint(spec.ContactPoints))
		if rotateRuntimeMatchesSpec(out, *spec) {
			out.LocalTunnelAddr = firstNonEmpty(out.LocalTunnelAddr, ipsec.FormatScopedTunnelAddress(spec.LocalTunnelAddr, spec.InterfaceName, spec.NetNS))
			out.PeerTunnelAddr = firstNonEmpty(out.PeerTunnelAddr, ipsec.FormatScopedTunnelAddress(spec.PeerTunnelAddr, spec.InterfaceName, spec.NetNS))
		}
	}
	return out
}

func rotateRuntimeMatchesDesired(runtime rotateRuntimeView, desired inspect.DesiredLink) bool {
	if desired.InterfaceName != "" && runtime.InterfaceName != "" && desired.InterfaceName != runtime.InterfaceName {
		return false
	}
	if desired.XFRMIfID != 0 && runtime.XFRMIfID != 0 && desired.XFRMIfID != runtime.XFRMIfID {
		return false
	}
	if desired.TransportID != "" && runtime.RuntimeID != "" && desired.TransportID != runtime.RuntimeID {
		return false
	}
	return true
}

func rotateRuntimeMatchesSpec(runtime rotateRuntimeView, spec ipsec.TransportLinkSpec) bool {
	if spec.InterfaceName != "" && runtime.InterfaceName != "" && spec.InterfaceName != runtime.InterfaceName {
		return false
	}
	if spec.XFRMIfID != 0 && runtime.XFRMIfID != 0 && spec.XFRMIfID != runtime.XFRMIfID {
		return false
	}
	if spec.TransportID != "" && runtime.RuntimeID != "" && spec.TransportID != runtime.RuntimeID {
		return false
	}
	return true
}

func rotateRuntimeStaged(link inspect.LinkView, spec *ipsec.TransportLinkSpec, sas []linkSAState) rotateRuntimeView {
	generation := link.Rotation.StagedGeneration
	if generation == 0 {
		return rotateRuntimeView{}
	}
	out := rotateRuntimeView{
		State:           "expected_new",
		Generation:      generation,
		Port:            debugStagedPort(spec, generation),
		RuntimeID:       link.Rotation.StagedIKEName,
		ChildSAName:     link.Rotation.StagedChildSAName,
		InterfaceName:   link.Rotation.StagedInterfaceName,
		XFRMIfID:        link.Rotation.StagedXFRMIfID,
		LocalTunnelAddr: link.Rotation.StagedLocalTunnelAddr,
		PeerTunnelAddr:  link.Rotation.StagedPeerTunnelAddr,
	}
	linkID := link.LinkID
	provider := ipsec.ProviderStrongSwan
	if spec != nil {
		linkID = firstNonEmpty(linkID, spec.LinkID)
		provider = firstNonEmpty(spec.Provider, provider)
	}
	if linkID != "" {
		out.RuntimeID = firstNonEmpty(out.RuntimeID, ipsec.RuntimeConnectionID(linkID, generation, provider))
		out.XFRMIfID = firstNonZeroUint32(out.XFRMIfID, ipsec.RuntimeXFRMIfID(linkID, generation, provider))
		out.InterfaceName = firstNonEmpty(out.InterfaceName, ipsec.StableInterfaceName(out.XFRMIfID))
	}
	if out.RuntimeID != "" {
		out.ChildSAName = firstNonEmpty(out.ChildSAName, out.RuntimeID+"-child")
	}
	if sa, ok := stagedSAForRuntime(out, sas); ok {
		out.Endpoint = firstNonEmpty(out.Endpoint, firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint))
		out.Port = firstNonEmpty(out.Port, debugEndpointPort(firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint)))
	}
	return out
}

func stagedSAForRuntime(runtime rotateRuntimeView, sas []linkSAState) (linkSAState, bool) {
	for _, sa := range sas {
		if runtime.XFRMIfID != 0 && sa.XFRMIfID == runtime.XFRMIfID {
			return sa, true
		}
		if nonEmptyMatches(runtime.RuntimeID, sa.Name, sa.ChildSA) ||
			nonEmptyMatches(runtime.ChildSAName, sa.Name, sa.ChildSA) {
			return sa, true
		}
	}
	return linkSAState{}, false
}

func matchingRotateSAs(link inspect.LinkView, sas []linkSAState) []linkSAState {
	out := make([]linkSAState, 0, len(sas))
	for _, sa := range sas {
		if rotateSAMatchesLink(link, sa) {
			out = append(out, sa)
		}
	}
	return out
}

func rotateSAMatchesLink(link inspect.LinkView, sa linkSAState) bool {
	if !linkSAMatchesPathKey(link, sa) {
		return false
	}
	if sa.XFRMIfID != 0 && (sa.XFRMIfID == link.XFRMIfID || sa.XFRMIfID == link.Rotation.StagedXFRMIfID) {
		return true
	}
	return nonEmptyMatches(link.ID, sa.Name, sa.ChildSA) ||
		nonEmptyMatches(link.TransportID, sa.Name, sa.ChildSA) ||
		nonEmptyMatches(link.ChildSAName, sa.Name, sa.ChildSA) ||
		nonEmptyMatches(link.Rotation.StagedIKEName, sa.Name, sa.ChildSA) ||
		nonEmptyMatches(link.Rotation.StagedChildSAName, sa.Name, sa.ChildSA)
}

func linkSAMatchesPathKey(link inspect.LinkView, sa linkSAState) bool {
	family := debugPathKeyFamily(link.PathKey)
	if family == "" {
		return true
	}
	endpointFamily := debugSAEndpointFamily(sa)
	return endpointFamily == "" || endpointFamily == family
}

func debugPathKeyFamily(pathKey string) string {
	if !strings.HasPrefix(pathKey, "family:") {
		return ""
	}
	family := strings.TrimPrefix(pathKey, "family:")
	if family == ipsec.FamilyIPv4 || family == ipsec.FamilyIPv6 {
		return family
	}
	return ""
}

func debugSAEndpointFamily(sa linkSAState) string {
	endpoint := firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint)
	host := debugEndpointHost(endpoint)
	if host == "" {
		return ""
	}
	return ipsecFamily(host)
}

func debugEndpointHost(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return strings.Trim(host, "[]")
	}
	if strings.HasPrefix(endpoint, "[") {
		if end := strings.Index(endpoint, "]"); end > 1 {
			return endpoint[1:end]
		}
	}
	return endpoint
}

func nonEmptyMatches(filter string, values ...string) bool {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" {
		return false
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), filter) {
			return true
		}
	}
	return false
}

func linkSAStatesFromIPsecSAs(sas []ipsec.SAState) []linkSAState {
	out := make([]linkSAState, 0, len(sas))
	for _, sa := range sas {
		out = append(out, linkSAState{
			Name:           sa.Name,
			Peer:           sa.Peer,
			ChildSA:        sa.ChildSA,
			IKEState:       sa.IKEState,
			ChildState:     sa.ChildState,
			XFRMIfID:       sa.XFRMIfID,
			ReqID:          sa.ReqID,
			LocalIdentity:  sa.LocalIdentity,
			RemoteIdentity: sa.RemoteIdentity,
			LocalEndpoint:  sa.LocalEndpoint,
			RemoteEndpoint: sa.RemoteEndpoint,
			Endpoint:       sa.Endpoint,
			Established:    sa.Established,
		})
	}
	return out
}

func firstNonZeroUint64(values ...uint64) uint64 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func firstNonZeroUint32(values ...uint32) uint32 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func printManualPortRotateResult(mode string, result *manualPortRotateResult) {
	if result == nil {
		return
	}
	fmt.Printf("mode: %s\n", mode)
	fmt.Printf("zone: %s\n", result.Zone)
	fmt.Printf("previous_generation: %d\n", result.PreviousGeneration)
	fmt.Printf("current_generation: %d\n", result.CurrentGeneration)
	if result.PreviousGeneration > 0 {
		fmt.Printf("previous_ike: %d\n", result.PreviousIKE)
		fmt.Printf("previous_natt: %d\n", result.PreviousNATT)
		fmt.Printf("previous_valid_until: %d\n", result.PreviousValidUntil)
	}
	fmt.Printf("current_ike: %d\n", result.CurrentIKE)
	fmt.Printf("current_natt: %d\n", result.CurrentNATT)
}

func forceLocalIPsecPortRotate(config *appConfig, state *stateFile, now time.Time) (*manualPortRotateResult, error) {
	if config == nil {
		config = defaultAppConfig()
	}
	if state == nil || state.Network == nil {
		return nil, fmt.Errorf("state is nil")
	}
	if state.ManagedZone == zone.RootZone || !state.ManagedZone.Valid() {
		return nil, fmt.Errorf("managed zone is required")
	}
	if len(state.ZonePrivateKey) == 0 {
		return nil, fmt.Errorf("managed zone private key is required")
	}
	mode := config.IPsec.PortMode
	if mode == "" {
		mode = ipsec.PortModeFixed
	}
	if mode != ipsec.PortModeRange {
		return nil, fmt.Errorf("manual port rotate requires ipsec.port_mode=range, got %q", mode)
	}
	if now.IsZero() {
		now = time.Now()
	}
	existing := existingIPsecPortRecord(state)
	previous := existing
	if previous == nil {
		previous = previousIPsecPortRecord(state)
	}
	prevState := ipsecPortRecordStateFromMeta(state)
	if prevState == nil {
		prevState = ipsecPortRecordStateFromRecord(existing)
	}
	nextGeneration := uint64(1)
	if prevState != nil && prevState.Generation > 0 {
		nextGeneration = prevState.Generation + 1
	}
	record, err := ipsec.PlanPortRecord(ipsec.PortPlanOptions{
		Mode:          mode,
		Range:         &config.IPsec.PortRange,
		FixedIKE:      uint16(ipsec.DefaultIKEPort),
		FixedNATT:     uint16(ipsec.DefaultNATTPort),
		Generation:    nextGeneration,
		Previous:      previous,
		PreviousGrace: config.IPsec.PortPreviousGrace,
		Now:           now,
	})
	if err != nil {
		return nil, err
	}
	changed, err := putSignedIPsecRecordIfChanged(state, state.ManagedZone, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, record, now)
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, fmt.Errorf("manual port rotate produced unchanged ipsec/ports record")
	}
	state.IPsecPortRecord = &ipsecPortRecordState{
		Mode:       record.Mode,
		Range:      record.Range,
		Generation: record.Current.Generation,
		UpdatedAt:  record.UpdatedAt,
	}
	result := &manualPortRotateResult{
		Zone:              state.ManagedZone,
		CurrentGeneration: record.Current.Generation,
		CurrentIKE:        record.Current.IKE.Advertised,
		CurrentNATT:       record.Current.NATT.Advertised,
	}
	if previous != nil && previous.Current != nil {
		result.PreviousGeneration = previous.Current.Generation
		result.PreviousIKE = previous.Current.IKE.Advertised
		result.PreviousNATT = previous.Current.NATT.Advertised
	}
	if len(record.Previous) > 0 {
		result.PreviousValidUntil = record.Previous[0].ValidUntil
	}
	return result, nil
}
