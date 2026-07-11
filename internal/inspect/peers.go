package inspect

import (
	"fmt"
	"sort"
	"strings"
	"time"

	higgsstate "github.com/Catofes/higgs/internal/state"
	"github.com/Catofes/higgs/pkg/core/zone"
)

type PeerSetInput struct {
	RuntimeIDs   []string
	BootstrapIDs []string
	SignedIDs    []string
	LocalIDs     []string
}

type PeerEndpointInput struct {
	BootstrapAddr  string
	Signed         []PeerSignedEndpoint
	SelectedAddr   string
	ObservedAddr   string
	ObservedSource string
	Grace          []PeerGraceEndpoint
}

type PeerSignedEndpoint struct {
	Address      string
	Port         uint16
	Protocol     string
	Scope        string
	Source       string
	Priority     int
	LastObserved int64
}

type PeerGraceEndpoint struct {
	Addr string
}

type PeerEndpointView struct {
	Addr         string `json:"addr"`
	Address      string `json:"address,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Source       string `json:"source,omitempty"`
	Priority     int    `json:"priority,omitempty"`
	LastObserved int64  `json:"last_observed,omitempty"`
	Selected     bool   `json:"selected,omitempty"`
}

type EndpointDebugView struct {
	ReflectorError  string
	LocalCandidates []EndpointCandidateView
	DiscoveredPeers []DiscoveredPeerEndpointsView
}

type EndpointDebugInput struct {
	ReflectorError      string
	HasPublicReflectors bool
	LocalCandidates     []EndpointCandidateView
	Discovered          map[string][]PeerSignedEndpoint
}

type EndpointCandidateView struct {
	Address  string
	Port     uint16
	Scope    string
	Priority int
	Source   string
}

type DiscoveredPeerEndpointsView struct {
	PeerID    string
	Endpoints []PeerSignedEndpoint
}

func BuildEndpointDebug(input EndpointDebugInput) EndpointDebugView {
	view := EndpointDebugView{
		LocalCandidates: append([]EndpointCandidateView(nil), input.LocalCandidates...),
	}
	sort.SliceStable(view.LocalCandidates, func(i, j int) bool {
		return endpointCandidateLess(view.LocalCandidates[i], view.LocalCandidates[j])
	})
	if input.ReflectorError != "" && input.HasPublicReflectors {
		view.ReflectorError = input.ReflectorError
	}
	peerIDs := make([]string, 0, len(input.Discovered))
	for peerID := range input.Discovered {
		peerIDs = append(peerIDs, peerID)
	}
	sort.Strings(peerIDs)
	for _, peerID := range peerIDs {
		endpoints := append([]PeerSignedEndpoint(nil), input.Discovered[peerID]...)
		sort.SliceStable(endpoints, func(i, j int) bool {
			return signedEndpointLess(endpoints[i], endpoints[j])
		})
		view.DiscoveredPeers = append(view.DiscoveredPeers, DiscoveredPeerEndpointsView{
			PeerID:    peerID,
			Endpoints: endpoints,
		})
	}
	return view
}

func endpointCandidateLess(a, b EndpointCandidateView) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	if a.Scope != b.Scope {
		return a.Scope < b.Scope
	}
	if a.Address != b.Address {
		return a.Address < b.Address
	}
	return a.Port < b.Port
}

func signedEndpointLess(a, b PeerSignedEndpoint) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if a.LastObserved != b.LastObserved {
		return a.LastObserved > b.LastObserved
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	if a.Scope != b.Scope {
		return a.Scope < b.Scope
	}
	if a.Address != b.Address {
		return a.Address < b.Address
	}
	if a.Port != b.Port {
		return a.Port < b.Port
	}
	return a.Protocol < b.Protocol
}

// PeerStatusInfo is the derived runtime status view for a peer. Producers
// compute it from committed state and runtime observations; presenters render
// it without depending on app-private stateFile internals.
type PeerStatusInfo struct {
	PeerID            string        `json:"peer_id"`
	Zone              zone.ZonePath `json:"zone"`
	State             string        `json:"state"`
	Reason            string        `json:"reason,omitempty"`
	Detail            string        `json:"detail,omitempty"`
	LastSeenUnix      int64         `json:"last_seen_unix,omitempty"`
	LastSyncUnix      int64         `json:"last_sync_unix,omitempty"`
	LastEndpointUnix  int64         `json:"last_endpoint_change_unix,omitempty"`
	LastReconcileUnix int64         `json:"last_reconcile_unix,omitempty"`
	DesiredLinks      int           `json:"desired_links,omitempty"`
	ActualLinks       int           `json:"actual_links,omitempty"`
	UpLinks           int           `json:"up_links,omitempty"`
	OfflineSinceUnix  int64         `json:"offline_since_unix,omitempty"`
	NextCleanupUnix   int64         `json:"next_cleanup_unix,omitempty"`
}

type PeerDebugView struct {
	PeerID           string
	Source           string
	ConfiguredAddr   string
	ResolvedAddr     string
	Status           string
	LastSuccess      string
	LastError        string
	Backoff          string
	NextRetry        string
	KnownEndpoint    string
	DiscoveredAddr   string
	ObservedAddr     string
	ObservedStatus   string
	LastUpdateSource string
	LastRelay        string
	RelaySuppression string
	SyncFlow         PeerSyncFlowView
	DatagramStats    PeerDatagramStatsView
	ObjectPullStats  PeerObjectPullStatsView
}

type PeerDebugInput struct {
	PeerID         string
	Source         string
	ConfiguredAddr string
	ResolvedAddr   string
	higgsstate.PeerRuntimeState
	Now time.Time
}

type PeerRuntimeDebugInput struct {
	PeerID         string
	Source         string
	ConfiguredAddr string
	ResolvedAddr   string
	State          higgsstate.PeerRuntimeState
	Now            time.Time
}

type PeerSyncFlowView struct {
	ActivePullState     string
	ActivePullLastEvent string
	ActivePullUpdated   string
	HintAccepted        int64
	HintSuppressed      int64
	LastHint            string
	LastHintReason      string
	LastHintSuppression string
	ReadOnlyResponder   int64
	LastResponder       string
	LastResponderKind   string
	LastResponderZone   string
}

type PeerDatagramStatsView struct {
	TooLargeDropped           int64
	DigestOnlyAnnounces       int64
	ChunkFallbacks            int64
	ChunkRepairNACKs          int64
	ChunkRepairChunks         int64
	ChunkRepairIgnored        int64
	LastCatalogRootHex        string
	LastCatalogZoneCount      int
	LastCatalogCursor         string
	LastCatalogPageEntries    int
	LastCatalogRejectedReason string
	LastCatalog               string
	LastTooLarge              string
	LastTooLargeDirection     string
	LastTooLargeObject        string
	LastTooLargeZone          string
	LastTooLargeKey           string
	LastTooLargeBytes         int
	LastTooLargeLimit         int
}

type PeerObjectPullStatsView struct {
	Attempts               int64
	Successes              int64
	Failures               int64
	LargeObjectUnreachable int64
	Last                   string
	LastObject             string
	LastZone               string
	LastKey                string
	LastBytes              int
	LastSourcePeer         string
	LastUnreachable        bool
	LastError              string
}

func BuildPeerDebugFromRuntime(input PeerRuntimeDebugInput) PeerDebugView {
	return BuildPeerDebug(PeerDebugInput{
		PeerID:           input.PeerID,
		Source:           input.Source,
		ConfiguredAddr:   input.ConfiguredAddr,
		ResolvedAddr:     input.ResolvedAddr,
		PeerRuntimeState: input.State,
		Now:              input.Now,
	})
}

func BuildPeerDebug(input PeerDebugInput) PeerDebugView {
	return PeerDebugView{
		PeerID:           input.PeerID,
		Source:           input.Source,
		ConfiguredAddr:   input.ConfiguredAddr,
		ResolvedAddr:     input.ResolvedAddr,
		Status:           peerDebugStatus(input, input.Now),
		LastSuccess:      formatPeerDebugLastSuccess(input.LastSyncUnix),
		LastError:        input.LastError,
		Backoff:          formatPeerDebugBackoff(input.BackoffUntilUnix, input.Now),
		NextRetry:        formatPeerDebugNextRetry(input.BackoffUntilUnix, input.Now),
		KnownEndpoint:    input.ResolvedAddr,
		DiscoveredAddr:   input.DiscoveredAddr,
		ObservedAddr:     input.ObservedAddr,
		ObservedStatus:   formatPeerDebugObservedPath(input, input.Now),
		LastUpdateSource: input.LastUpdateSource,
		LastRelay:        formatPeerDebugUnixTime(input.LastRelayUnix),
		RelaySuppression: formatPeerDebugRelaySuppression(input.LastRelaySuppression, input.LastRelaySuppressedAt),
		SyncFlow:         BuildPeerSyncFlowFromRuntime(input.PeerRuntimeState),
		DatagramStats:    BuildPeerDatagramStatsFromRuntime(input.PeerRuntimeState),
		ObjectPullStats:  BuildPeerObjectPullStatsFromRuntime(input.PeerRuntimeState),
	}
}

func BuildPeerSyncFlowFromRuntime(state higgsstate.PeerRuntimeState) PeerSyncFlowView {
	return PeerSyncFlowView{
		ActivePullState:     state.ActivePullState,
		ActivePullLastEvent: state.ActivePullLastEvent,
		ActivePullUpdated:   formatPeerDebugUnixTime(state.ActivePullUpdatedUnix),
		HintAccepted:        state.HintAccepted,
		HintSuppressed:      state.HintSuppressed,
		LastHint:            formatPeerDebugUnixTime(state.LastHintUnix),
		LastHintReason:      state.LastHintReason,
		LastHintSuppression: state.LastHintSuppression,
		ReadOnlyResponder:   state.ReadOnlyResponder,
		LastResponder:       formatPeerDebugUnixTime(state.LastResponderUnix),
		LastResponderKind:   state.LastResponderKind,
		LastResponderZone:   state.LastResponderZone,
	}
}

func BuildPeerDatagramStatsFromRuntime(state higgsstate.PeerRuntimeState) PeerDatagramStatsView {
	if state.DatagramStats == nil {
		return PeerDatagramStatsView{}
	}
	return buildPeerDatagramStatsView(*state.DatagramStats)
}

func BuildPeerObjectPullStatsFromRuntime(state higgsstate.PeerRuntimeState) PeerObjectPullStatsView {
	if state.ObjectPullStats == nil {
		return PeerObjectPullStatsView{}
	}
	return buildPeerObjectPullStatsView(*state.ObjectPullStats)
}

func buildPeerDatagramStatsView(input higgsstate.PeerDatagramStats) PeerDatagramStatsView {
	return PeerDatagramStatsView{
		TooLargeDropped:           input.TooLargeDropped,
		DigestOnlyAnnounces:       input.DigestOnlyAnnounces,
		ChunkFallbacks:            input.ChunkFallbacks,
		ChunkRepairNACKs:          input.ChunkRepairNACKs,
		ChunkRepairChunks:         input.ChunkRepairChunks,
		ChunkRepairIgnored:        input.ChunkRepairIgnored,
		LastCatalogRootHex:        input.LastCatalogRootHex,
		LastCatalogZoneCount:      input.LastCatalogZoneCount,
		LastCatalogCursor:         input.LastCatalogCursor,
		LastCatalogPageEntries:    input.LastCatalogPageEntries,
		LastCatalogRejectedReason: input.LastCatalogRejectedReason,
		LastCatalog:               formatPeerDebugUnixTime(input.LastCatalogUnix),
		LastTooLarge:              formatPeerDebugUnixTime(input.LastTooLargeUnix),
		LastTooLargeDirection:     input.LastTooLargeDirection,
		LastTooLargeObject:        input.LastTooLargeObject,
		LastTooLargeZone:          input.LastTooLargeZone,
		LastTooLargeKey:           input.LastTooLargeKey,
		LastTooLargeBytes:         input.LastTooLargeBytes,
		LastTooLargeLimit:         input.LastTooLargeLimit,
	}
}

func buildPeerObjectPullStatsView(input higgsstate.PeerObjectPullStats) PeerObjectPullStatsView {
	return PeerObjectPullStatsView{
		Attempts:               input.Attempts,
		Successes:              input.Successes,
		Failures:               input.Failures,
		LargeObjectUnreachable: input.LargeObjectUnreachable,
		Last:                   formatPeerDebugUnixTime(input.LastUnix),
		LastObject:             input.LastObject,
		LastZone:               input.LastZone,
		LastKey:                input.LastKey,
		LastBytes:              input.LastBytes,
		LastSourcePeer:         input.LastSourcePeer,
		LastUnreachable:        input.LastUnreachable,
		LastError:              input.LastError,
	}
}

func BuildPeerIDs(input PeerSetInput) []string {
	local := make(map[string]bool, len(input.LocalIDs))
	for _, id := range input.LocalIDs {
		if id != "" {
			local[id] = true
		}
	}
	seen := map[string]bool{}
	add := func(ids []string) {
		for _, id := range ids {
			if id == "" || local[id] || seen[id] {
				continue
			}
			seen[id] = true
		}
	}
	add(input.RuntimeIDs)
	add(input.BootstrapIDs)
	add(input.SignedIDs)
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return ZonePathLess(out[i], out[j]) })
	return out
}

func peerDebugStatus(input PeerDebugInput, now time.Time) string {
	if peerDebugBackoffRemaining(input.BackoffUntilUnix, now) > 0 {
		return "backoff"
	}
	if input.LastError != "" {
		return "stale"
	}
	if input.LastSyncUnix == 0 {
		return "unknown"
	}
	if now.Sub(time.Unix(input.LastSyncUnix, 0)) > 2*time.Minute {
		return "stale"
	}
	return "online"
}

func formatPeerDebugLastSuccess(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return formatPeerDebugUnixTime(unix)
}

func formatPeerDebugBackoff(untilUnix int64, now time.Time) string {
	remaining := peerDebugBackoffRemaining(untilUnix, now)
	if remaining <= 0 {
		return "-"
	}
	return remaining.Round(time.Second).String()
}

func formatPeerDebugNextRetry(untilUnix int64, now time.Time) string {
	if peerDebugBackoffRemaining(untilUnix, now) <= 0 {
		return "-"
	}
	return formatPeerDebugUnixTime(untilUnix)
}

func formatPeerDebugUnixTime(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

func formatPeerDebugRelaySuppression(reason string, suppressedAtUnix int64) string {
	if reason == "" {
		return "-"
	}
	at := formatPeerDebugUnixTime(suppressedAtUnix)
	if at == "never" {
		return reason
	}
	return fmt.Sprintf("%s at=%s", reason, at)
}

func formatPeerDebugObservedPath(input PeerDebugInput, now time.Time) string {
	if input.ObservedAddr == "" {
		return "-"
	}
	state := "expired"
	if input.ObservedUntilUnix != 0 && now.Before(time.Unix(input.ObservedUntilUnix, 0)) {
		state = "active"
	}
	return fmt.Sprintf("%s until=%s last_seen=%s last_success=%s failures=%d source=%s",
		state,
		formatPeerDebugUnixTime(input.ObservedUntilUnix),
		formatPeerDebugUnixTime(input.ObservedLastSeenUnix),
		formatPeerDebugUnixTime(input.ObservedLastSyncUnix),
		input.ObservedFailureCount,
		debugDash(input.ObservedSource),
	)
}

func peerDebugBackoffRemaining(untilUnix int64, now time.Time) time.Duration {
	if untilUnix == 0 {
		return 0
	}
	until := time.Unix(untilUnix, 0)
	if !until.After(now) {
		return 0
	}
	return until.Sub(now)
}

func PeerKnown(input PeerSetInput, peerID string) bool {
	if peerID == "" {
		return false
	}
	for _, local := range input.LocalIDs {
		if peerID == local {
			return false
		}
	}
	for _, ids := range [][]string{input.RuntimeIDs, input.BootstrapIDs, input.SignedIDs} {
		for _, id := range ids {
			if peerID == id {
				return true
			}
		}
	}
	return false
}

func ZonePathLess(a, b string) bool {
	aLabels, aOK := zonePathLabels(a)
	bLabels, bOK := zonePathLabels(b)
	if !aOK || !bOK {
		return a < b
	}
	for i := 0; i < len(aLabels) && i < len(bLabels); i++ {
		if aLabels[i] != bLabels[i] {
			return aLabels[i] < bLabels[i]
		}
	}
	if len(aLabels) != len(bLabels) {
		return len(aLabels) < len(bLabels)
	}
	return a < b
}

func zonePathLabels(path string) ([]string, bool) {
	zp := zone.ZonePath(path)
	if !zp.Valid() {
		return nil, false
	}
	if zp.IsRoot() {
		return nil, true
	}
	labels := strings.Split(strings.TrimSuffix(path, "."), ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return labels, true
}

func BuildPeerEndpoints(input PeerEndpointInput) []PeerEndpointView {
	var out []PeerEndpointView
	appendEndpoint := func(ep PeerEndpointView) {
		if ep.Addr == "" && ep.Address != "" && ep.Port != 0 {
			ep.Addr = fmt.Sprintf("%s:%d", ep.Address, ep.Port)
		}
		if ep.Protocol == "" {
			ep.Protocol = "udp"
		}
		for i := range out {
			if out[i].Addr == ep.Addr && out[i].Source == ep.Source {
				if ep.Selected {
					out[i].Selected = true
				}
				return
			}
		}
		out = append(out, ep)
	}
	if input.BootstrapAddr != "" {
		appendEndpoint(PeerEndpointView{
			Addr:     input.BootstrapAddr,
			Source:   "bootstrap",
			Selected: input.SelectedAddr == input.BootstrapAddr,
		})
	}
	for _, ep := range input.Signed {
		addr := ""
		if ep.Address != "" && ep.Port != 0 {
			addr = fmt.Sprintf("%s:%d", ep.Address, ep.Port)
		}
		appendEndpoint(PeerEndpointView{
			Addr:         addr,
			Address:      ep.Address,
			Port:         ep.Port,
			Protocol:     ep.Protocol,
			Scope:        ep.Scope,
			Source:       firstNonEmpty(ep.Source, "signed"),
			Priority:     ep.Priority,
			LastObserved: ep.LastObserved,
			Selected:     input.SelectedAddr == addr,
		})
	}
	if input.SelectedAddr != "" {
		appendEndpoint(PeerEndpointView{Addr: input.SelectedAddr, Source: "selected", Selected: true})
	}
	if input.ObservedAddr != "" {
		appendEndpoint(PeerEndpointView{
			Addr:     input.ObservedAddr,
			Source:   firstNonEmpty(input.ObservedSource, "observed"),
			Selected: input.SelectedAddr == "",
		})
	}
	for _, grace := range input.Grace {
		appendEndpoint(PeerEndpointView{Addr: grace.Addr, Source: "observed_grace"})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Selected != out[j].Selected {
			return out[i].Selected
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}
