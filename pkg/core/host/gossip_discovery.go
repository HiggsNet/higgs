package host

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

var ErrGossipCheckpointWriterRequired = errors.New("gossip checkpoint writer is required")

// GossipDiscoveryInput is the detached common/runtime input used to rebuild
// the in-memory peer address book. Suppressed peers remain dialable but do not
// regain a checkpoint until their platform cleanup marker is cleared.
type GossipDiscoveryInput struct {
	LocalPeerID   string
	ManagedZone   zone.ZonePath
	Network       *zone.NetworkState
	Peers         map[string]corestate.PeerCheckpoint
	Suppressed    map[string]bool
	Bootstrap     map[string]*net.UDPAddr
	EndpointGrace time.Duration
	SourceOrder   []string
}

type GossipPeerAddressUpdate struct {
	SetAddresses    []*net.UDPAddr
	RemoveAddresses bool
	ObservedPaths   []gossip.ObservedPath
	PreferObserved  bool
	RemoveObserved  bool
}

type GossipDiscoveryPlan struct {
	KnownPeerIDs []string
	Peers        map[string]GossipPeerAddressUpdate
	Patches      map[string]corestate.PeerCheckpointPatch
}

type GossipCheckpointWriter interface {
	UpdatePeerCheckpoints(context.Context, map[string]corestate.PeerCheckpointPatch) (corestate.CommitResult, error)
}

// RefreshGossipDiscovery persists checkpoint changes before publishing the
// rebuilt, loss-tolerant address book to the live transport.
func (runtime *Runtime) RefreshGossipDiscovery(ctx context.Context, input GossipDiscoveryInput, now time.Time, writer GossipCheckpointWriter, transport *gossip.Transport) error {
	if !runtime.gossipDiscoveryAvailable() {
		return ErrRuntimeStopped
	}
	plan := PlanGossipDiscovery(input, now)
	if len(plan.Patches) > 0 {
		if writer == nil {
			return ErrGossipCheckpointWriterRequired
		}
		if _, err := writer.UpdatePeerCheckpoints(ctx, plan.Patches); err != nil {
			return err
		}
	}
	ApplyGossipDiscoveryPlan(transport, plan)
	return nil
}

// RestoreGossipObservedPath republishes one already-persisted observed path
// into the loss-tolerant address book after packet/checkpoint processing.
func (runtime *Runtime) RestoreGossipObservedPath(input GossipDiscoveryInput, peerID string, now time.Time, transport *gossip.Transport) error {
	if !runtime.gossipDiscoveryAvailable() {
		return ErrRuntimeStopped
	}
	if transport == nil || peerID == "" {
		return nil
	}
	paths, prefer, ok := discoveryObservedPaths(input, peerID, input.Peers[peerID], now)
	if !ok {
		transport.RemoveObservedPeerAddr(peerID)
		return nil
	}
	transport.SetObservedPeerPaths(peerID, paths, prefer)
	return nil
}

func (runtime *Runtime) gossipDiscoveryAvailable() bool {
	if runtime == nil {
		return false
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	return !runtime.stopped
}

func PlanGossipDiscovery(input GossipDiscoveryInput, now time.Time) GossipDiscoveryPlan {
	plan := GossipDiscoveryPlan{Peers: make(map[string]GossipPeerAddressUpdate), Patches: make(map[string]corestate.PeerCheckpointPatch)}
	if input.Network == nil {
		return plan
	}
	plan.KnownPeerIDs = verifiedDiscoveryPeers(input, now)
	discovered := gossip.ExtractPeerEndpointsAt(input.Network, now)
	active := make(map[string]bool)

	for peerID, bootstrap := range input.Bootstrap {
		addrs := buildDiscoveryAddresses(discovered[peerID], bootstrap, input.Peers[peerID], input.EndpointGrace, input.SourceOrder, now)
		if len(addrs) > 0 {
			update := plan.Peers[peerID]
			update.SetAddresses = addrs
			plan.Peers[peerID] = update
		}
	}
	for peerID, entries := range discovered {
		if peerID == input.LocalPeerID || peerID == string(input.ManagedZone) || len(entries) == 0 {
			continue
		}
		current := input.Peers[peerID]
		addrs := buildDiscoveryAddresses(entries, input.Bootstrap[peerID], current, input.EndpointGrace, input.SourceOrder, now)
		if len(addrs) == 0 {
			continue
		}
		active[peerID] = true
		update := plan.Peers[peerID]
		update.SetAddresses = addrs
		plan.Peers[peerID] = update
		if input.Suppressed[peerID] {
			continue
		}
		addr := addrs[0].String()
		if current.DiscoveredEndpoint != addr || current.DiscoveredAtUnix != now.Unix() {
			plan.Patches[peerID] = mergeDiscoveryPatch(plan.Patches[peerID], corestate.PeerCheckpointPatch{
				DiscoveredEndpoint: corestate.PatchField[string]{Set: true, Value: addr},
				DiscoveredAtUnix:   corestate.PatchField[int64]{Set: true, Value: now.Unix()},
			})
		}
	}

	peerIDs := make([]string, 0, len(input.Peers))
	for peerID := range input.Peers {
		peerIDs = append(peerIDs, peerID)
	}
	sort.Strings(peerIDs)
	for _, peerID := range peerIDs {
		peer := input.Peers[peerID]
		update := plan.Peers[peerID]
		if peer.ObservedEndpoint != "" && !discoveryObservedActive(peer, now) {
			update.RemoveObserved = true
			plan.Patches[peerID] = mergeDiscoveryPatch(plan.Patches[peerID], clearObservedDiscoveryPatch())
		} else if paths, prefer, ok := discoveryObservedPaths(input, peerID, peer, now); ok {
			update.ObservedPaths, update.PreferObserved = paths, prefer
		} else {
			update.RemoveObserved = true
		}
		if peer.DiscoveredEndpoint != "" && !active[peerID] && input.Bootstrap[peerID] == nil &&
			peerID != input.LocalPeerID && peerID != string(input.ManagedZone) && len(discovered[peerID]) == 0 &&
			len(recentDiscoveryAddresses(nil, peer, input.EndpointGrace, now)) == 0 {
			update.RemoveAddresses = true
			plan.Patches[peerID] = mergeDiscoveryPatch(plan.Patches[peerID], corestate.PeerCheckpointPatch{
				DiscoveredEndpoint: corestate.PatchField[string]{Set: true}, DiscoveredAtUnix: corestate.PatchField[int64]{Set: true},
			})
		}
		plan.Peers[peerID] = update
	}
	return plan
}

func ApplyGossipDiscoveryPlan(transport *gossip.Transport, plan GossipDiscoveryPlan) {
	if transport == nil {
		return
	}
	for _, peerID := range plan.KnownPeerIDs {
		transport.AddKnownPeerID(peerID)
	}
	peerIDs := make([]string, 0, len(plan.Peers))
	for peerID := range plan.Peers {
		peerIDs = append(peerIDs, peerID)
	}
	sort.Strings(peerIDs)
	for _, peerID := range peerIDs {
		update := plan.Peers[peerID]
		if update.RemoveObserved {
			transport.RemoveObservedPeerAddr(peerID)
		} else if len(update.ObservedPaths) > 0 {
			transport.SetObservedPeerPaths(peerID, update.ObservedPaths, update.PreferObserved)
		}
		if update.RemoveAddresses {
			transport.RemovePeerAddrs(peerID)
		} else if len(update.SetAddresses) > 0 {
			transport.SetPeerAddrs(peerID, update.SetAddresses)
		}
	}
}

func verifiedDiscoveryPeers(input GossipDiscoveryInput, now time.Time) []string {
	network := *input.Network
	network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	seen := make(map[string]bool)
	add := func(path zone.ZonePath) {
		id := string(path)
		if id != "" && id != input.LocalPeerID && id != string(input.ManagedZone) {
			seen[id] = true
		}
	}
	for path := range network.Zones {
		if photoncrypto.VerifyChain(&network, path, now) == nil {
			add(path)
		}
	}
	for parent, state := range network.Zones {
		if state == nil || photoncrypto.VerifyChain(&network, parent, now) != nil {
			continue
		}
		for child := range state.Delegations {
			if !network.IsZoneRevoked(child, now) {
				add(child)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func discoveryObservedPaths(input GossipDiscoveryInput, peerID string, peer corestate.PeerCheckpoint, now time.Time) ([]gossip.ObservedPath, bool, bool) {
	if !discoveryObservedActive(peer, now) || !discoveryPeerVerified(input, peerID, now) {
		return nil, false, false
	}
	addr, err := net.ResolveUDPAddr("udp", peer.ObservedEndpoint)
	if err != nil {
		return nil, false, false
	}
	paths := []gossip.ObservedPath{{Addr: addr, Until: time.Unix(peer.ObservedUntilUnix, 0)}}
	seen := map[string]bool{peer.ObservedEndpoint: true}
	for _, entry := range peer.ObservedGraceEndpoints {
		if entry.Endpoint == "" || seen[entry.Endpoint] || entry.UntilUnix == 0 || !now.Before(time.Unix(entry.UntilUnix, 0)) {
			continue
		}
		grace, err := net.ResolveUDPAddr("udp", entry.Endpoint)
		if err != nil {
			continue
		}
		seen[entry.Endpoint] = true
		paths = append(paths, gossip.ObservedPath{Addr: grace, Until: time.Unix(entry.UntilUnix, 0)})
	}
	prefer := peer.LastFailure != nil || peer.DiscoveredEndpoint == "" || discoveryAddressPrivate(peer.DiscoveredEndpoint)
	return paths, prefer, true
}

func discoveryPeerVerified(input GossipDiscoveryInput, peerID string, now time.Time) bool {
	path := zone.ZonePath(peerID)
	if input.Network == nil || !path.Valid() || path == input.ManagedZone {
		return false
	}
	network := *input.Network
	network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	return photoncrypto.VerifyChain(&network, path, now) == nil
}

func discoveryObservedActive(peer corestate.PeerCheckpoint, now time.Time) bool {
	return peer.ObservedEndpoint != "" && peer.ObservedUntilUnix != 0 && now.Before(time.Unix(peer.ObservedUntilUnix, 0))
}

func discoveryAddressPrivate(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast())
}

func clearObservedDiscoveryPatch() corestate.PeerCheckpointPatch {
	return corestate.PeerCheckpointPatch{
		ObservedEndpoint:  corestate.PatchField[string]{Set: true},
		ObservedFirstUnix: corestate.PatchField[int64]{Set: true},
		ObservedLastUnix:  corestate.PatchField[int64]{Set: true},
		ObservedSyncUnix:  corestate.PatchField[int64]{Set: true},
		ObservedUntilUnix: corestate.PatchField[int64]{Set: true},
		ObservedFailures:  corestate.PatchField[int]{Set: true},
	}
}

func mergeDiscoveryPatch(a, b corestate.PeerCheckpointPatch) corestate.PeerCheckpointPatch {
	if b.DiscoveredEndpoint.Set {
		a.DiscoveredEndpoint = b.DiscoveredEndpoint
	}
	if b.DiscoveredAtUnix.Set {
		a.DiscoveredAtUnix = b.DiscoveredAtUnix
	}
	if b.ObservedEndpoint.Set {
		a.ObservedEndpoint = b.ObservedEndpoint
	}
	if b.ObservedFirstUnix.Set {
		a.ObservedFirstUnix = b.ObservedFirstUnix
	}
	if b.ObservedLastUnix.Set {
		a.ObservedLastUnix = b.ObservedLastUnix
	}
	if b.ObservedSyncUnix.Set {
		a.ObservedSyncUnix = b.ObservedSyncUnix
	}
	if b.ObservedUntilUnix.Set {
		a.ObservedUntilUnix = b.ObservedUntilUnix
	}
	if b.ObservedFailures.Set {
		a.ObservedFailures = b.ObservedFailures
	}
	return a
}

func buildDiscoveryAddresses(entries []gossip.EndpointEntry, bootstrap *net.UDPAddr, peer corestate.PeerCheckpoint, grace time.Duration, order []string, now time.Time) []*net.UDPAddr {
	if len(order) == 0 {
		order = []string{"advertise", "bootstrap", "reflector", "interface"}
	}
	bySource := make(map[string][]*net.UDPAddr)
	for _, entry := range sortedDiscoveryEndpoints(entries) {
		addr, err := entry.UDPAddr()
		if err == nil {
			source := strings.ToLower(entry.Source)
			if source == "" {
				source = "interface"
			}
			bySource[source] = appendDiscoveryAddress(bySource[source], addr)
		}
	}
	bySource["recent"] = recentDiscoveryAddresses(nil, peer, grace, now)
	var out []*net.UDPAddr
	seen := make(map[string]bool)
	appendSource := func(source string) {
		if source == "bootstrap" && bootstrap != nil {
			if !seen[bootstrap.String()] {
				copied := *bootstrap
				out = append(out, &copied)
				seen[bootstrap.String()] = true
			}
			return
		}
		for _, addr := range bySource[source] {
			if !seen[addr.String()] {
				out = append(out, addr)
				seen[addr.String()] = true
			}
		}
	}
	for _, source := range order {
		appendSource(source)
	}
	for _, source := range []string{"recent", "bootstrap", "advertise", "reflector", "interface"} {
		appendSource(source)
	}
	return out
}

func recentDiscoveryAddresses(out []*net.UDPAddr, peer corestate.PeerCheckpoint, grace time.Duration, now time.Time) []*net.UDPAddr {
	if peer.DiscoveredEndpoint == "" || peer.LastSyncUnix == 0 || peer.LastFailure != nil {
		return out
	}
	if grace <= 0 {
		grace = gossip.DefaultEndpointGrace
	}
	if now.After(time.Unix(peer.LastSyncUnix, 0).Add(grace)) {
		return out
	}
	addr, err := net.ResolveUDPAddr("udp", peer.DiscoveredEndpoint)
	if err != nil {
		return out
	}
	return appendDiscoveryAddress(out, addr)
}

func appendDiscoveryAddress(out []*net.UDPAddr, addr *net.UDPAddr) []*net.UDPAddr {
	if addr == nil {
		return out
	}
	for _, current := range out {
		if current.IP.Equal(addr.IP) && current.Port == addr.Port {
			return out
		}
	}
	copied := *addr
	return append(out, &copied)
}

func sortedDiscoveryEndpoints(entries []gossip.EndpointEntry) []gossip.EndpointEntry {
	out := append([]gossip.EndpointEntry(nil), entries...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := discoveryEndpointRank(out[i]), discoveryEndpointRank(out[j])
		if ri != rj {
			return ri < rj
		}
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].LastObserved > out[j].LastObserved
	})
	return out
}

func discoveryEndpointRank(entry gossip.EndpointEntry) int {
	ip := net.ParseIP(entry.Address)
	if ip == nil {
		return 3
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return 2
	}
	return 0
}
