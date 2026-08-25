package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/internal/observability"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

const relayMinInterval = time.Second
const defaultSyncRoundTimeout = 5 * time.Second
const syncOnceResponderQuiet = 500 * time.Millisecond
const maxRelayFanoutPerUpdate = 8
const rejectedDigestTTL = 10 * time.Minute
const observedPathTTL = 3 * time.Minute
const observedPathMigrationGrace = time.Minute

var collectSyncLocalEndpoints = gossip.CollectLocalEndpointsWithReflectors

var udpChunkAssemblies = gossip.NewChunkAssemblyStore()
var udpSentChunkCache = gossip.NewSentChunkCache()

type SyncRuntime struct {
	App           *Runtime
	Config        *syncConfigFile
	Transport     *gossip.Transport
	TransportDeps *SyncTransportDeps
	Observability *observability.PeerObservabilityStore

	// reloadStateStamp is only accessed by the daemon event loop.  It avoids
	// reopening and decoding the complete state database when nothing changed.
	reloadStateStamp stateFileStamp
}

type stateFileStamp struct {
	path     string
	info     os.FileInfo
	revision uint64
}

type SyncTransportDeps struct {
	KnownPeers map[string]*net.UDPAddr
	Replay     *gossip.ReplayWindow
	Quotas     *gossip.PeerQuotas
	Log        func(gossip.Event)
}

func newSyncRuntime(config *syncConfigFile, transport *gossip.Transport, app *Runtime) *SyncRuntime {
	return &SyncRuntime{
		App:       app,
		Config:    config,
		Transport: transport,
	}
}

func defaultSyncTransportDeps(config *syncConfigFile) *SyncTransportDeps {
	return &SyncTransportDeps{
		KnownPeers: configuredKnownPeers(config),
		Replay:     gossip.NewReplayWindow(0),
		Quotas:     gossip.NewPeerQuotas(gossip.QuotaConfig{}),
		Log:        syncDebugLogger(config),
	}
}

func (sr *SyncRuntime) syncTransportDeps() *SyncTransportDeps {
	if sr.TransportDeps != nil {
		return sr.TransportDeps
	}
	return defaultSyncTransportDeps(sr.Config)
}

func (sr *SyncRuntime) now() time.Time {
	if sr != nil && sr.App != nil {
		return sr.App.Now()
	}
	return time.Now()
}

func (sr *SyncRuntime) logger() *appLogger {
	if sr == nil {
		return newAppLogger(nil)
	}
	logger := newAppLogger(sr.Config)
	if sr.App != nil {
		logger.now = sr.App.Now
	}
	return logger
}

func (sr *SyncRuntime) saveStateSnapshotAtRevision(state *stateFile, revision uint64) error {
	if sr == nil || sr.App == nil {
		return saveState(state)
	}
	// Until a complete, stable post-close marker is available, reload must not
	// trust the previous token.
	sr.reloadStateStamp = stateFileStamp{}
	info, err := saveStateAtWithFileInfo(sr.App.StatePath, state)
	if err != nil {
		return err
	}
	if info != nil {
		sr.reloadStateStamp = stateFileStamp{path: sr.App.StatePath, info: info, revision: revision}
	}
	return nil
}

func (sr *SyncRuntime) saveStateMetaSnapshotAtRevision(state *stateFile, revision uint64) error {
	if sr == nil || sr.App == nil {
		return saveStateMeta(state)
	}
	sr.reloadStateStamp = stateFileStamp{}
	info, err := saveStateMetaAtWithFileInfo(sr.App.StatePath, state)
	if err != nil {
		return err
	}
	if info != nil {
		sr.reloadStateStamp = stateFileStamp{path: sr.App.StatePath, info: info, revision: revision}
	}
	return nil
}

func (sr *SyncRuntime) loadState() (*stateFile, error) {
	if sr != nil && sr.App != nil {
		return sr.App.LoadState()
	}
	return loadState()
}

func syncStatus(verbose bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := daemonStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		fmt.Fprintf(os.Stdout, "daemon: online peer_id=%s\n", response.PeerID)
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	config, err := rt.SyncConfig(state)
	if err != nil {
		return err
	}
	return writeSyncStatus(os.Stdout, state, config, rt.Now(), verbose)
}

func writeSyncStatus(w io.Writer, state *stateFile, config *syncConfigFile, now time.Time, verbose bool) error {
	return inspecttext.WriteSyncStatus(w, buildSyncStatusView(state, config, now, verbose))
}

func buildSyncStatusView(state *stateFile, config *syncConfigFile, now time.Time, verbose bool) inspect.SyncStatusView {
	digests := corestate.ZoneDigests(state.Network)
	view := inspect.SyncStatusView{
		PeerID:       config.PeerID,
		ListenAddr:   config.ListenAddr,
		KnownPeers:   len(config.Bootstrap),
		KnownZones:   len(digests),
		LocalRootHex: hex.EncodeToString(globalRootHash(digests)),
		Limits: inspect.SyncLimitsView{
			MaxDatagramBytes: config.MaxMessageBytes,
			MaxSyncZones:     config.MaxSyncZones,
			MaxSyncRecords:   config.MaxSyncRecords,
			WireVersion:      gossip.WireVersion,
			WireCodec:        "msgpack",
		},
		Verbose: verbose,
	}
	discovered := gossip.ExtractPeerEndpoints(state.Network)
	if verbose {
		known := configuredKnownPeers(config)
		view.AllowlistSource = "bootstrap+discovery"
		view.BootstrapPeers = len(config.Bootstrap)
		for peerID := range discovered {
			if !isBootstrapPeer(config, peerID) {
				view.DiscoveredPeers++
			}
		}
		for _, peer := range config.Bootstrap {
			resolved := "-"
			if addr := known[peer.ID]; addr != nil {
				resolved = addr.String()
			}
			peerState := state.SyncPeers[peer.ID]
			view.Bootstrap = append(view.Bootstrap, syncVerbosePeerView(peer.ID, peer.Addr, resolved, "", peerState, now))
		}
		discoveredIDs := make([]string, 0, len(discovered))
		for peerID, entries := range discovered {
			if isBootstrapPeer(config, peerID) {
				continue
			}
			discoveredIDs = append(discoveredIDs, peerID)
			_ = entries
		}
		sort.Slice(discoveredIDs, func(i, j int) bool { return inspect.ZonePathLess(discoveredIDs[i], discoveredIDs[j]) })
		for _, peerID := range discoveredIDs {
			entries := discovered[peerID]
			peerState := state.SyncPeers[peerID]
			addr := "-"
			if len(entries) > 0 {
				addr = fmt.Sprintf("%s:%d", entries[0].Address, entries[0].Port)
			}
			view.Discovered = append(view.Discovered, syncVerbosePeerView(peerID, "", "", addr, peerState, now))
		}
	}
	for _, peer := range config.Bootstrap {
		peerState := state.SyncPeers[peer.ID]
		peerDebug := inspect.BuildPeerDebugFromRuntime(inspect.PeerRuntimeDebugInput{
			PeerID:         peer.ID,
			ConfiguredAddr: peer.Addr,
			State:          peerState,
			Now:            now,
		})
		lastError := peerState.LastError
		if lastError == "" {
			lastError = "-"
		}
		view.Peers = append(view.Peers, inspect.SyncPeerSummaryView{
			PeerID:     peer.ID,
			Addr:       peer.Addr,
			Status:     peerDebug.Status,
			LastSync:   peerDebug.LastSuccess,
			KnownZones: len(digests),
			LastError:  lastError,
			NextRetry:  peerDebug.NextRetry,
		})
	}
	for _, digest := range digests {
		zs := state.Network.Zones[digest.Zone]
		view.Zones = append(view.Zones, inspect.SyncZoneSummaryView{
			Zone:        string(digest.Zone),
			RootHex:     hex.EncodeToString(digest.RootHash),
			Records:     len(zs.Records),
			History:     inspect.ZoneHistoryCount(zs),
			Delegations: len(zs.Delegations),
			Revocations: len(zs.Revocations),
		})
	}
	sort.SliceStable(view.Bootstrap, func(i, j int) bool {
		return inspect.ZonePathLess(view.Bootstrap[i].PeerID, view.Bootstrap[j].PeerID)
	})
	sort.SliceStable(view.Discovered, func(i, j int) bool {
		return inspect.ZonePathLess(view.Discovered[i].PeerID, view.Discovered[j].PeerID)
	})
	sort.SliceStable(view.Peers, func(i, j int) bool {
		return inspect.ZonePathLess(view.Peers[i].PeerID, view.Peers[j].PeerID)
	})
	sort.SliceStable(view.Zones, func(i, j int) bool {
		return inspect.ZonePathLess(view.Zones[i].Zone, view.Zones[j].Zone)
	})
	return view
}

func syncVerbosePeerView(peerID, configuredAddr, resolvedAddr, addr string, peerState syncPeerState, now time.Time) inspect.SyncVerbosePeerView {
	return inspect.SyncVerbosePeerView{
		PeerDebugView: inspect.BuildPeerDebugFromRuntime(inspect.PeerRuntimeDebugInput{
			PeerID:         peerID,
			ConfiguredAddr: configuredAddr,
			ResolvedAddr:   resolvedAddr,
			State:          peerState,
			Now:            now,
		}),
		Addr: addr,
	}
}

func syncServe(ctx context.Context) error {
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
	logger := newAppLogger(config)
	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	transport, err := service.Sync.openTransport(service.currentState())
	if err != nil {
		return err
	}
	packetCh, stopRecv := gossip.StartPacketReceiver(ctx, transport, gossip.DefaultPacketReceiveBuffer, func(err error) {
		logger.Warn("transport", "receive_failed", map[string]any{"error": err})
	})
	defer stopRecv()
	service.Sync.Transport = transport
	objectPullListener, err := objectPullTCPServe(objectPullTCPAddr(transport.LocalAddr().String()), service.objectPullResponse)
	if err != nil {
		return err
	}
	if objectPullListener != nil {
		defer objectPullListener.Close()
		logger.Info("object_pull", "serve_started", map[string]any{"addr": objectPullListener.Addr()})
	}
	service.objectPullPool.Start(ctx)
	defer service.objectPullPool.Stop()
	logger.Info("sync", "serve_started", map[string]any{
		"peer_id": config.PeerID,
		"addr":    transport.LocalAddr(),
	})
	for {
		select {
		case <-ctx.Done():
			return nil
		case packet := <-packetCh:
			if packet == nil {
				continue
			}
			if err := service.processPacketEvent(packet, ctx); err != nil {
				logger.Warn("gossip", "packet_failed", addGossipErrorFields(map[string]any{
					"peer_id": packet.Message.PeerID,
					"type":    packet.Message.Type,
					"reason":  gossip.RejectReason(err),
					"error":   err,
				}, err))
			}
		case hostEvent := <-service.hostRuntime.Events():
			if event, ok := service.hostRuntime.GossipEventFor(hostEvent); ok {
				service.handleSyncEvent(ctx, event)
			}
		case result := <-service.objectPullResults:
			service.acceptObjectPullResult(result)
		}
	}
}

func syncOnce(peerID string) error {
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
	service := newDaemonService(rt, state, config, defaultDaemonInterval)
	transport, err := service.Sync.openTransport(service.currentState())
	if err != nil {
		return err
	}
	defer transport.Close()
	service.Sync.Transport = transport
	objectPullListener, err := objectPullTCPServe(objectPullTCPAddr(transport.LocalAddr().String()), service.objectPullResponse)
	if err != nil {
		return err
	}
	if objectPullListener != nil {
		defer objectPullListener.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultSyncRoundTimeout)
	defer cancel()
	service.objectPullPool.Start(ctx)
	defer service.objectPullPool.Stop()
	service.updateDiscoveredPeers()
	if err := service.startHintedSyncSession(peerID, "sync_once"); err != nil {
		return err
	}
	var responderQuietUntil time.Time
	for {
		drained := false
		if service.hostRuntime.Gossip.Session(peerID) == nil && service.hostRuntime.PendingEventCount() == 0 && len(service.objectPullResults) == 0 {
			drained = true
			if responderQuietUntil.IsZero() {
				responderQuietUntil = time.Now().Add(syncOnceResponderQuiet)
			}
			if !time.Now().Before(responderQuietUntil) {
				return nil
			}
		} else {
			responderQuietUntil = time.Time{}
		}
		select {
		case <-ctx.Done():
			if session := service.hostRuntime.Gossip.Session(peerID); session != nil && session.PendingCount() > 0 {
				pending := session.PendingZones()
				return &syncPendingZonesError{zones: pending}
			}
			return errors.New("sync receive timed out")
		case hostEvent := <-service.hostRuntime.Events():
			responderQuietUntil = time.Time{}
			if event, ok := service.hostRuntime.GossipEventFor(hostEvent); ok {
				service.handleSyncEvent(ctx, event)
			}
		case result := <-service.objectPullResults:
			responderQuietUntil = time.Time{}
			service.acceptObjectPullResult(result)
		default:
			deadline := time.Now().Add(100 * time.Millisecond)
			if drained && !responderQuietUntil.IsZero() && responderQuietUntil.Before(deadline) {
				deadline = responderQuietUntil
			}
			packet, err := receiveWithContext(ctx, transport, deadline)
			if err == nil {
				responderQuietUntil = time.Time{}
				if handleErr := service.processPacketEvent(packet, ctx); handleErr != nil {
					return handleErr
				}
				continue
			}
			if ctx.Err() != nil {
				continue
			}
			if drained && !responderQuietUntil.IsZero() && !time.Now().Before(responderQuietUntil) {
				return nil
			}
			if !isReceiveTimeout(err) {
				return err
			}
		}
	}
}

func syncRun(ctx context.Context, interval time.Duration) error {
	return daemonRun(ctx, interval)
}

func (sr *SyncRuntime) reloadStateIfChanged(previous []corestate.ZoneDigest) (*stateFile, bool, error) {
	return sr.reloadStateIfChangedWith(previous, sr.loadState)
}

// reloadStateIfChangedWith reloads only when the state DB changed. The loader
// argument keeps the file-change gate independently testable; production uses
// sr.loadState.
func (sr *SyncRuntime) reloadStateIfChangedWith(previous []corestate.ZoneDigest, load func() (*stateFile, error)) (*stateFile, bool, error) {
	path := sr.stateFilePath()
	var before os.FileInfo
	if path != "" {
		if info, err := os.Stat(path); err == nil {
			before = info
			if sr.reloadStateStamp.matches(path, info) {
				// This exact file version was already produced or observed by
				// the previous poll. There is no new external state to return.
				return nil, false, nil
			}
		}
	}

	latest, err := load()
	if err != nil {
		return nil, false, err
	}
	if path != "" {
		// Do not cache a token if the file moved while it was being read. That
		// makes the next loop reload once more instead of suppressing a newer
		// external write.
		if after, err := os.Stat(path); err == nil && sameStateFileInfo(before, after) {
			sr.reloadStateStamp = stateFileStamp{path: path, info: after}
		} else {
			sr.reloadStateStamp = stateFileStamp{}
		}
	}
	if !sameZoneDigests(previous, corestate.ZoneDigests(latest.Network)) {
		return latest, true, nil
	}
	return latest, false, nil
}

func (sr *SyncRuntime) stateFilePath() string {
	if sr != nil && sr.App != nil {
		return sr.App.StatePath
	}
	return ""
}

func (stamp stateFileStamp) matches(path string, info os.FileInfo) bool {
	return stamp.path == path && sameStateFileInfo(stamp.info, info)
}

func sameStateFileInfo(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) &&
		a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func zonePathStrings(paths []zone.ZonePath) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		out = append(out, path.String())
	}
	return out
}

type syncPendingZonesError struct {
	zones []zone.ZonePath
}

func (e *syncPendingZonesError) Error() string {
	if e == nil {
		return "sync once timed out with pending zones"
	}
	if len(e.zones) == 0 {
		return "sync once timed out with pending zones"
	}
	return "sync once timed out with pending zones: " + strings.Join(zonePathStrings(e.zones), ",")
}

func (e *syncPendingZonesError) PendingZones() []string {
	if e == nil {
		return nil
	}
	return zonePathStrings(e.zones)
}

func sameZoneDigests(a, b []corestate.ZoneDigest) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Zone != b[i].Zone || !bytes.Equal(a[i].RootHash, b[i].RootHash) {
			return false
		}
	}
	return true
}

func shouldSkipRemoteZone(state *stateFile, peerID string, path zone.ZonePath, rootHash []byte, now time.Time) bool {
	if state == nil {
		return true
	}
	if path == state.ManagedZone {
		// Never fetch or apply our own managed zone from a peer; we are the authority.
		return true
	}
	return isRejectedDigestActive(state, peerID, path, rootHash, now)
}

func isRejectedDigestActive(state *stateFile, peerID string, path zone.ZonePath, rootHash []byte, now time.Time) bool {
	if state == nil || peerID == "" || !path.Valid() || len(rootHash) == 0 {
		return false
	}
	peerState := state.SyncPeers[peerID]
	rejected, ok := peerState.RejectedDigests[rejectedDigestKey(path)]
	if !ok {
		rejected, ok = peerState.RejectedDigests[path.String()]
		if !ok {
			return false
		}
	}
	if rejected.Object != "" && rejected.Object != "zone" {
		return false
	}
	if rejected.RootHashHex != hex.EncodeToString(rootHash) {
		return false
	}
	return rejected.UntilUnix != 0 && now.Before(time.Unix(rejected.UntilUnix, 0))
}

// recordRejectedDigest mutates state.SyncPeers. The caller must hold the write
// lock on state.
func recordRejectedDigest(state *stateFile, peerID string, digest corestate.ZoneDigest, reason string, now time.Time) {
	if state == nil || peerID == "" || !digest.Zone.Valid() || len(digest.RootHash) == 0 {
		return
	}
	if reason == "" {
		reason = "verify_failed"
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	if peerState.RejectedDigests == nil {
		peerState.RejectedDigests = make(map[string]rejectedDigestState)
	}
	peerState.RejectedDigests[rejectedDigestKey(digest.Zone)] = rejectedDigestState{
		Zone:           digest.Zone,
		Object:         "zone",
		RootHashHex:    hex.EncodeToString(digest.RootHash),
		Reason:         reason,
		RejectedAtUnix: now.Unix(),
		UntilUnix:      now.Add(rejectedDigestTTL).Unix(),
	}
	state.SyncPeers[peerID] = peerState
}

// clearRejectedDigest mutates state.SyncPeers. The caller must hold the write
// lock on state.
func clearRejectedDigest(state *stateFile, peerID string, path zone.ZonePath) {
	if state == nil || peerID == "" || !path.Valid() {
		return
	}
	peerState := state.SyncPeers[peerID]
	if len(peerState.RejectedDigests) == 0 {
		return
	}
	delete(peerState.RejectedDigests, rejectedDigestKey(path))
	delete(peerState.RejectedDigests, path.String())
	state.SyncPeers[peerID] = peerState
}

func rejectedDigestKey(path zone.ZonePath) string {
	return "zone:" + path.String()
}

func shouldRelayToPeer(peerState syncPeerState, peerID, sourcePeerID string, now time.Time) (bool, string) {
	switch {
	case peerID == "":
		return false, "empty_peer_id"
	case peerID == sourcePeerID:
		return false, "source_peer"
	case backoffRemaining(peerState, now) > 0:
		return false, "backoff"
	case peerState.LastRelayUnix != 0 && now.Sub(time.Unix(peerState.LastRelayUnix, 0)) < relayMinInterval:
		return false, "relay_throttled"
	default:
		return true, ""
	}
}

// recordRelaySuccess mutates state.SyncPeers. The caller must hold the write
// lock on state.
func recordRelaySuccess(state *stateFile, peerID, sourcePeerID string, now time.Time) {
	if state == nil || peerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	peerState.LastRelayUnix = now.Unix()
	peerState.LastUpdateSource = sourcePeerID
	peerState.LastRelaySuppression = ""
	peerState.LastRelaySuppressedAt = 0
	state.SyncPeers[peerID] = peerState
}

// recordRelaySuppression mutates state.SyncPeers. The caller must hold the write
// lock on state.
func recordRelaySuppression(state *stateFile, peerID, reason string, now time.Time) {
	if state == nil || peerID == "" || reason == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	peerState.LastRelaySuppression = reason
	peerState.LastRelaySuppressedAt = now.Unix()
	state.SyncPeers[peerID] = peerState
}

// recordVerifiedObservedPath mutates state.SyncPeers. The caller must hold the
// write lock on state.
func recordVerifiedObservedPath(state *stateFile, peerID string, addr *net.UDPAddr, source gossip.MessageType, now time.Time) {
	if state == nil || addr == nil || !peerChainVerified(state, peerID, now) {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	addrString := addr.String()
	if peerState.ObservedAddr != addrString || peerState.ObservedFirstSeenUnix == 0 {
		if observedPathActive(peerState, now) && peerState.ObservedAddr != "" && peerState.ObservedAddr != addrString {
			peerState.ObservedGraceAddrs = appendObservedGraceAddr(peerState.ObservedGraceAddrs, peerState.ObservedAddr, now.Add(observedPathMigrationGrace), now)
		}
		peerState.ObservedFirstSeenUnix = now.Unix()
		peerState.ObservedFailureCount = 0
	}
	peerState.ObservedAddr = addrString
	peerState.ObservedLastSeenUnix = now.Unix()
	peerState.ObservedUntilUnix = now.Add(observedPathTTL).Unix()
	peerState.ObservedSource = string(source)
	peerState.ObservedGraceAddrs = pruneObservedGraceAddrs(peerState.ObservedGraceAddrs, addrString, now)
	state.SyncPeers[peerID] = peerState
}

func observedPathActive(peerState syncPeerState, now time.Time) bool {
	return peerState.ObservedAddr != "" && peerState.ObservedUntilUnix != 0 && now.Before(time.Unix(peerState.ObservedUntilUnix, 0))
}

func appendObservedGraceAddr(grace []observedGraceAddrState, addr string, until, now time.Time) []observedGraceAddrState {
	if addr == "" || !now.Before(until) {
		return pruneObservedGraceAddrs(grace, "", now)
	}
	out := pruneObservedGraceAddrs(grace, addr, now)
	return append(out, observedGraceAddrState{Addr: addr, UntilUnix: until.Unix()})
}

func pruneObservedGraceAddrs(grace []observedGraceAddrState, current string, now time.Time) []observedGraceAddrState {
	if len(grace) == 0 {
		return nil
	}
	out := grace[:0]
	for _, entry := range grace {
		if entry.Addr == "" || entry.Addr == current || entry.UntilUnix == 0 || !now.Before(time.Unix(entry.UntilUnix, 0)) {
			continue
		}
		duplicate := false
		for _, existing := range out {
			if existing.Addr == entry.Addr {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, entry)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func observedPathPreferFirst(peerState syncPeerState, now time.Time) bool {
	return observedPathActive(peerState, now) && (peerState.LastError != "" || peerState.DiscoveredAddr == "" || discoveredAddrIsPrivate(peerState.DiscoveredAddr))
}

func discoveredAddrIsPrivate(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func peerChainVerified(state *stateFile, peerID string, now time.Time) bool {
	if state == nil || state.Network == nil || peerID == "" {
		return false
	}
	path := zone.ZonePath(peerID)
	if !path.Valid() {
		return false
	}
	if state.ManagedZone == path {
		return false
	}
	// Validation hooks are runtime-only fields. Configure them on a shallow
	// Network root so callers using an immutable StateStore view do not mutate
	// the structurally shared committed Network.
	network := *state.Network
	configureValidation(&network)
	return photoncrypto.VerifyChain(&network, path, now) == nil
}

// seedObservedPeerPaths mutates transport observed paths based on a read-only
// state view.
func (sr *SyncRuntime) seedObservedPeerPaths(state *stateFile) {
	if sr == nil || state == nil || sr.Transport == nil {
		return
	}
	now := sr.now()
	for peerID := range state.SyncPeers {
		sr.seedObservedPeerPathAt(state, peerID, now)
	}
}

func (sr *SyncRuntime) seedObservedPeerPathAt(state *stateFile, peerID string, now time.Time) {
	if sr == nil || state == nil || sr.Transport == nil || peerID == "" {
		return
	}
	// pruneObservedGraceAddrs compacts its input slice in place. Detach the
	// peer so seeding transport state cannot mutate a committed state
	// child through the shared slice backing array.
	peerState := cloneSyncPeerState(state.SyncPeers[peerID])
	if !observedPathActive(peerState, now) || !peerChainVerified(state, peerID, now) {
		sr.Transport.RemoveObservedPeerAddr(peerID)
		return
	}
	addr, err := net.ResolveUDPAddr("udp", peerState.ObservedAddr)
	if err != nil {
		sr.Transport.RemoveObservedPeerAddr(peerID)
		return
	}
	paths := []gossip.ObservedPath{{Addr: addr, Until: time.Unix(peerState.ObservedUntilUnix, 0)}}
	for _, entry := range pruneObservedGraceAddrs(peerState.ObservedGraceAddrs, peerState.ObservedAddr, now) {
		graceAddr, err := net.ResolveUDPAddr("udp", entry.Addr)
		if err != nil {
			continue
		}
		paths = append(paths, gossip.ObservedPath{Addr: graceAddr, Until: time.Unix(entry.UntilUnix, 0)})
	}
	sr.Transport.SetObservedPeerPaths(peerID, paths, observedPathPreferFirst(peerState, now))
}

func (sr *SyncRuntime) openTransport(state *stateFile) (*gossip.Transport, error) {
	deps := sr.syncTransportDeps()
	transport, err := gossip.Listen(sr.transportConfig(deps))
	if err != nil {
		return nil, err
	}
	sr.Transport = transport
	sr.seedTransportPeers(state, deps)
	return transport, nil
}

func (sr *SyncRuntime) transportConfig(deps *SyncTransportDeps) gossip.Config {
	return gossip.Config{
		PeerID:          sr.Config.PeerID,
		ListenAddr:      sr.Config.ListenAddr,
		KnownPeers:      deps.KnownPeers,
		MaxMessageBytes: sr.Config.MaxMessageBytes,
		Replay:          deps.Replay,
		Quotas:          deps.Quotas,
		Clock:           sr.now,
		Log:             deps.Log,
	}
}

func (sr *SyncRuntime) seedTransportPeers(state *stateFile, deps *SyncTransportDeps) {
	if state == nil || sr.Transport == nil {
		return
	}
	addVerifiedZonePeers(state, sr.Transport, sr.Config)
	sr.seedObservedPeerPaths(state)
	for peerID, entries := range gossip.ExtractPeerEndpoints(state.Network) {
		if peerID == sr.Config.PeerID || peerID == string(state.ManagedZone) {
			continue
		}
		if _, ok := deps.KnownPeers[peerID]; ok {
			continue
		}
		var addrs []*net.UDPAddr
		for _, entry := range sortedEndpointEntriesForDial(entries) {
			addr, err := entry.UDPAddr()
			if err != nil {
				continue
			}
			addrs = append(addrs, addr)
		}
		if len(addrs) > 0 {
			sr.Transport.SetPeerAddrs(peerID, addrs)
		}
	}
}

func outboundSyncPeersAt(state *stateFile, config *syncConfigFile, now time.Time) []string {
	seen := make(map[string]bool)
	var out []string
	for _, peer := range config.Bootstrap {
		if peer.ID == "" || seen[peer.ID] {
			continue
		}
		seen[peer.ID] = true
		out = append(out, peer.ID)
	}
	for peerID := range gossip.ExtractPeerEndpoints(state.Network) {
		if peerID == config.PeerID || peerID == string(state.ManagedZone) || seen[peerID] {
			continue
		}
		seen[peerID] = true
		out = append(out, peerID)
	}
	for peerID, peerState := range state.SyncPeers {
		if peerID == config.PeerID || peerID == string(state.ManagedZone) || seen[peerID] {
			continue
		}
		if !observedPathActive(peerState, now) || !peerChainVerified(state, peerID, now) {
			continue
		}
		seen[peerID] = true
		out = append(out, peerID)
	}
	return out
}

func isBootstrapPeer(config *syncConfigFile, peerID string) bool {
	for _, peer := range config.Bootstrap {
		if peer.ID == peerID {
			return true
		}
	}
	return false
}

func listenPortFromAddr(addr string) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return uint16(gossip.DefaultPort)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return uint16(gossip.DefaultPort)
	}
	return uint16(port)
}

func (sr *SyncRuntime) publishEndpointRecordInState(state *stateFile) (bool, error) {
	config := sr.Config
	if state == nil || state.ManagedZone == zone.RootZone || len(state.ZonePrivateKey) == 0 || autoJoinPending(state) {
		return false, nil
	}
	if config != nil && config.DisableEndpointPublish {
		return sr.clearPublishedEndpointRecordInState(state)
	}
	port := listenPortFromAddr(config.ListenAddr)
	advertiseAddrs, reflectors := filterEndpointDiscoveryInputs(config, port)
	endpoints, reflectorErr := collectSyncLocalEndpoints(port, advertiseAddrs, reflectors, config.ReflectorTimeout, config.FilterPrivateIPv4)
	if reflectorErr != nil && len(gossip.ResolvePublicIPReflectors(reflectors)) > 0 {
		sr.logger().Warn("endpoint", "reflector_failed", map[string]any{"error": reflectorErr})
	}
	now := sr.now()
	var previous *gossip.EndpointRecord

	zs := state.Network.Zones[state.ManagedZone]
	if zs != nil {
		if existing := zs.Records[gossip.EndpointRecordKeyUDP]; existing != nil {
			var er gossip.EndpointRecord
			if err := json.Unmarshal(existing.Value, &er); err == nil {
				previous = &er
			}
		}
	}
	recordValue := gossip.LocalEndpointsToRecordWithPolicy(endpoints, previous, now, config.EndpointTTL, config.EndpointGrace)
	value, err := json.Marshal(recordValue)
	if err != nil {
		return false, err
	}

	if zs != nil {
		if existing := zs.Records[gossip.EndpointRecordKeyUDP]; existing != nil {
			if bytes.Equal(existing.Value, value) || (gossip.EndpointRecordEndpointsEqual(previous, recordValue) && !endpointRefreshDue(previous, now, config.EndpointRefresh)) {
				return false, nil
			}
		}
	}

	record, err := buildSignedRecordAt(state, state.ManagedZone, gossip.EndpointRecordKeyUDP, value, "sync.endpoint", now)
	if err != nil {
		return false, err
	}
	if err := state.Network.Put(record); err != nil {
		return false, err
	}
	return true, nil
}

func endpointRefreshDue(previous *gossip.EndpointRecord, now time.Time, refresh time.Duration) bool {
	if previous == nil || len(previous.Endpoints) == 0 {
		return true
	}
	if refresh <= 0 {
		refresh = gossip.DefaultEndpointRefresh
	}
	base := previous.UpdatedAt
	if base == 0 {
		for _, ep := range previous.Endpoints {
			if ep.LastObserved > base {
				base = ep.LastObserved
			}
		}
	}
	if base == 0 {
		return true
	}
	return !now.Before(time.Unix(base, 0).Add(refresh))
}

// filterEndpointDiscoveryInputs returns the advertise addresses and reflectors
// to use when publishing local endpoints, respecting the endpoint_discovery
// configuration. loopback_only suppresses public IP reflectors and interface
// scans, keeping only loopback addresses and explicit loopback advertise_addrs.
// advertise_only uses only explicit advertise_addrs.
//
// When endpoint_discovery is unset, the daemon auto-detects loopback-only test
// deployments: if every configured bootstrap peer uses a loopback address, it
// behaves like loopback_only to avoid publishing unreachable public IPs that
// would starve loopback bootstrap paths.
func filterEndpointDiscoveryInputs(config *syncConfigFile, port uint16) (advertiseAddrs, reflectors []string) {
	mode := strings.ToLower(strings.TrimSpace(config.EndpointDiscovery))
	if mode == "" && allBootstrapAddrsLoopback(config.Bootstrap) {
		mode = "loopback_only"
	}
	switch mode {
	case "advertise_only":
		return config.AdvertiseAddrs, nil
	case "loopback_only":
		for _, addr := range config.AdvertiseAddrs {
			if host, _, err := net.SplitHostPort(addr); err == nil && isLoopbackIP(host) {
				advertiseAddrs = append(advertiseAddrs, addr)
			}
		}
		// Derive loopback endpoints from listen_addr. If listen_addr is not a
		// specific loopback address, fall back to the well-known loopback IPs.
		if host, _, err := net.SplitHostPort(config.ListenAddr); err == nil && isLoopbackIP(host) {
			advertiseAddrs = append(advertiseAddrs, net.JoinHostPort(host, strconv.Itoa(int(port))))
		} else {
			advertiseAddrs = append(advertiseAddrs, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
			advertiseAddrs = append(advertiseAddrs, net.JoinHostPort("::1", strconv.Itoa(int(port))))
		}
		return advertiseAddrs, nil
	case "", "all":
		return config.AdvertiseAddrs, config.Reflectors
	default:
		return config.AdvertiseAddrs, config.Reflectors
	}
}

func allBootstrapAddrsLoopback(peers []syncConfigPeer) bool {
	if len(peers) == 0 {
		return false
	}
	for _, peer := range peers {
		if peer.Addr == "" {
			return false
		}
		host, _, err := net.SplitHostPort(peer.Addr)
		if err != nil {
			host = peer.Addr
		}
		if !isLoopbackIP(host) {
			return false
		}
	}
	return true
}

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (sr *SyncRuntime) clearPublishedEndpointRecordInState(state *stateFile) (bool, error) {
	config := sr.Config
	zs := state.Network.Zones[state.ManagedZone]
	if zs == nil {
		return false, nil
	}
	existing := zs.Records[gossip.EndpointRecordKeyUDP]
	if existing == nil {
		return false, nil
	}
	var current gossip.EndpointRecord
	if err := json.Unmarshal(existing.Value, &current); err == nil && len(current.Endpoints) == 0 {
		return false, nil
	}
	now := sr.now()
	recordValue := gossip.LocalEndpointsToRecordWithPolicy(nil, nil, now, config.EndpointTTL, 0)
	value, err := json.Marshal(recordValue)
	if err != nil {
		return false, err
	}
	record, err := buildSignedRecordAt(state, state.ManagedZone, gossip.EndpointRecordKeyUDP, value, "sync.endpoint", now)
	if err != nil {
		return false, err
	}
	if err := state.Network.Put(record); err != nil {
		return false, err
	}
	return true, nil
}

func addVerifiedZonePeers(state *stateFile, transport *gossip.Transport, config *syncConfigFile) {
	newSyncRuntime(config, transport, nil).addVerifiedZonePeers(state)
}

// addVerifiedZonePeers mutates transport known-peer state based on a read-only
// state view.
func (sr *SyncRuntime) addVerifiedZonePeers(state *stateFile) {
	transport := sr.Transport
	config := sr.Config
	if state == nil || state.Network == nil {
		return
	}
	// Validation hooks are runtime-only. Install them on a shallow root so a
	// transport refresh never mutates the state view supplied by StateStore.
	network := *state.Network
	configureValidation(&network)
	now := sr.now()
	for path := range network.Zones {
		peerID := string(path)
		if peerID == config.PeerID || peerID == string(state.ManagedZone) {
			continue
		}
		if err := photoncrypto.VerifyChain(&network, path, now); err != nil {
			continue
		}
		transport.AddKnownPeerID(peerID)
	}
	for parentPath, zs := range network.Zones {
		if zs == nil || len(zs.Delegations) == 0 {
			continue
		}
		if err := photoncrypto.VerifyChain(&network, parentPath, now); err != nil {
			continue
		}
		for childPath := range zs.Delegations {
			peerID := string(childPath)
			if peerID == config.PeerID || peerID == string(state.ManagedZone) || network.IsZoneRevoked(childPath, now) {
				continue
			}
			transport.AddKnownPeerID(peerID)
		}
	}
}

// buildPeerAddrs merges bootstrap and discovered endpoint addresses according
// to the configured source order. Bootstrap addresses are never displaced by
// discovered addresses of a lower-priority source, preventing automatic
// endpoint discovery from overriding administrator-configured loopback/bootstrap
// addresses.
func buildPeerAddrs(_ string, entries []gossip.EndpointEntry, bootstrapAddr *net.UDPAddr, peerState syncPeerState, grace time.Duration, sourceOrder []string, now time.Time) []*net.UDPAddr {
	if len(sourceOrder) == 0 {
		sourceOrder = []string{"advertise", "bootstrap", "reflector", "interface"}
	}

	bySource := make(map[string][]*net.UDPAddr)
	for _, entry := range sortedEndpointEntriesForDial(entries) {
		addr, err := entry.UDPAddr()
		if err != nil {
			continue
		}
		src := strings.ToLower(entry.Source)
		if src == "" {
			src = "interface"
		}
		bySource[src] = appendUDPAddrOnce(bySource[src], addr)
	}
	if recent := appendRecentSuccessfulDiscoveredAddr(nil, peerState, grace, now); len(recent) > 0 {
		// Recent successful discovered addresses are treated as a high-priority
		// discovered source so they are not lost during churn.
		bySource["recent"] = recent
	}

	var addrs []*net.UDPAddr
	seen := make(map[string]bool)
	for _, source := range sourceOrder {
		switch source {
		case "bootstrap":
			if bootstrapAddr != nil && !seen[bootstrapAddr.String()] {
				copied := *bootstrapAddr
				addrs = append(addrs, &copied)
				seen[bootstrapAddr.String()] = true
			}
		case "recent":
			for _, addr := range bySource["recent"] {
				if !seen[addr.String()] {
					addrs = append(addrs, addr)
					seen[addr.String()] = true
				}
			}
		default:
			for _, addr := range bySource[source] {
				if !seen[addr.String()] {
					addrs = append(addrs, addr)
					seen[addr.String()] = true
				}
			}
		}
	}

	// If a configured source order omitted bootstrap or recent, still append
	// any remaining unseen addresses at the end as a safety net.
	for _, source := range []string{"recent", "bootstrap", "advertise", "reflector", "interface"} {
		if source == "bootstrap" && bootstrapAddr != nil && !seen[bootstrapAddr.String()] {
			copied := *bootstrapAddr
			addrs = append(addrs, &copied)
			seen[bootstrapAddr.String()] = true
			continue
		}
		for _, addr := range bySource[source] {
			if !seen[addr.String()] {
				addrs = append(addrs, addr)
				seen[addr.String()] = true
			}
		}
	}

	return addrs
}

func appendRecentSuccessfulDiscoveredAddr(addrs []*net.UDPAddr, peerState syncPeerState, grace time.Duration, now time.Time) []*net.UDPAddr {
	if peerState.DiscoveredAddr == "" || peerState.LastSyncUnix == 0 || peerState.LastError != "" {
		return addrs
	}
	if grace <= 0 {
		grace = gossip.DefaultEndpointGrace
	}
	if now.After(time.Unix(peerState.LastSyncUnix, 0).Add(grace)) {
		return addrs
	}
	addr, err := net.ResolveUDPAddr("udp", peerState.DiscoveredAddr)
	if err != nil {
		return addrs
	}
	return appendUDPAddrOnce(addrs, addr)
}

func appendUDPAddrOnce(addrs []*net.UDPAddr, addr *net.UDPAddr) []*net.UDPAddr {
	if addr == nil {
		return addrs
	}
	for _, existing := range addrs {
		if existing != nil && existing.IP.Equal(addr.IP) && existing.Port == addr.Port {
			return addrs
		}
	}
	copied := *addr
	return append(addrs, &copied)
}

func sortedEndpointEntriesForDial(entries []gossip.EndpointEntry) []gossip.EndpointEntry {
	out := append([]gossip.EndpointEntry(nil), entries...)
	sort.SliceStable(out, func(i, j int) bool {
		ri := endpointDialRank(out[i])
		rj := endpointDialRank(out[j])
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

func endpointDialRank(entry gossip.EndpointEntry) int {
	ip := net.ParseIP(entry.Address)
	if ip == nil {
		return 3
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return 2
	}
	return 0
}

func endpointEntryIsPrivate(entry gossip.EndpointEntry) bool {
	return endpointDialRank(entry) == 2
}

func receiveWithContext(ctx context.Context, transport *gossip.Transport, deadline time.Time) (*gossip.Packet, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		readDeadline := deadline
		// UDP reads are blocking syscalls.  We cap each read at 250 ms so the
		// caller can respond to context cancellation and (in daemon mode) its
		// own timers even when no gossip packets are arriving.  Timeouts are
		// routine and are no longer logged by the transport.
		shortDeadline := time.Now().Add(250 * time.Millisecond)
		if shortDeadline.Before(readDeadline) {
			readDeadline = shortDeadline
		}
		packet, err := receiveWithDeadline(transport, readDeadline)
		if err == nil {
			return packet, nil
		}
		if time.Now().After(deadline) || !isReceiveTimeout(err) {
			return nil, err
		}
	}
}

func receiveWithDeadline(transport *gossip.Transport, deadline time.Time) (*gossip.Packet, error) {
	if err := transport.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	for {
		packet, err := transport.Receive()
		if err == nil {
			return packet, nil
		}
		if time.Now().After(deadline) {
			return nil, errors.New("sync receive timed out")
		}
		if errors.Is(err, gossip.ErrUnknownPeer) || errors.Is(err, gossip.ErrAddrMismatch) || errors.Is(err, gossip.ErrMessageTooLarge) {
			continue
		}
		return nil, err
	}
}

func isReceiveTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout() || strings.Contains(err.Error(), "timed out")
}

func backoffRemaining(peerState syncPeerState, now time.Time) time.Duration {
	if peerState.BackoffUntilUnix == 0 {
		return 0
	}
	until := time.Unix(peerState.BackoffUntilUnix, 0)
	if !until.After(now) {
		return 0
	}
	return until.Sub(now)
}

func (sr *SyncRuntime) handleObjectChunkNACK(message *gossip.Message) error {
	if sr == nil || sr.Transport == nil || message == nil || message.ObjectChunkNACK == nil {
		return nil
	}
	chunks := udpSentChunkCache.Repair(message.PeerID, message.ObjectChunkNACK, sr.now())
	if len(chunks) == 0 {
		recordDatagramRepairNACK(sr.Observability, message.PeerID, true, sr.now())
		return nil
	}
	for _, chunk := range chunks {
		if err := sr.Transport.Send(message.PeerID, &gossip.Message{Type: gossip.MessageObjectChunk, ObjectChunk: chunk}); err != nil {
			return err
		}
	}
	recordDatagramRepairSent(sr.Observability, message.PeerID, len(chunks), sr.now())
	return nil
}

type datagramSendDiagnostics struct {
	Oversized      []gossip.OversizedDatagramObject
	ChunkFallbacks int
}

func sendDetachedSnapshotWithDiagnostics(snapshot *corestate.ZoneSnapshot, plan gossip.DatagramPlan, transport *gossip.Transport, peerID string, now time.Time, logger *appLogger) (datagramSendDiagnostics, error) {
	diag := datagramSendDiagnostics{Oversized: append([]gossip.OversizedDatagramObject(nil), plan.Oversized...)}
	for _, oversized := range plan.Oversized {
		if logger != nil && logger.debugEnabled() {
			logger.Debug("transport", "datagram_too_large", map[string]any{
				"peer_id": peerID, "object": oversized.Object, "zone": oversized.Zone,
				"key": oversized.Key, "bytes": oversized.Size, "limit": transport.MaxMessageBytes(), "action": "skip_udp",
			})
		}
	}
	for _, announce := range plan.Announces {
		if err := transport.Send(peerID, &gossip.Message{Type: gossip.MessageAnnounce, Announce: announce}); err != nil {
			return diag, err
		}
	}
	chunks, err := sendDetachedZoneSnapshotChunks(snapshot, transport, peerID, now)
	diag.ChunkFallbacks = chunks
	return diag, err
}

func sendDetachedZoneSnapshotChunks(snapshot *corestate.ZoneSnapshot, transport *gossip.Transport, peerID string, now time.Time) (int, error) {
	if snapshot == nil || transport == nil {
		return 0, nil
	}
	transferID := make([]byte, 16)
	if _, err := rand.Read(transferID); err != nil {
		return 0, fmt.Errorf("create chunk transfer id: %w", err)
	}
	chunks, err := gossip.BuildZoneSnapshotChunks(snapshot, transport.MaxMessageBytes(), transport.PeerID(), transferID)
	if err != nil {
		return 0, err
	}
	if !udpSentChunkCache.Put(peerID, transferID, chunks, now) {
		return 0, errors.New("chunk send cache limits exceeded")
	}
	sent := 0
	for _, chunk := range chunks {
		msg := &gossip.Message{
			Type:        gossip.MessageObjectChunk,
			ObjectChunk: chunk,
		}
		if err := transport.Send(peerID, msg); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func recordDatagramTooLarge(store *observability.PeerObservabilityStore, peerID, direction, object string, zoneName zone.ZonePath, key string, size, limit int, now time.Time) {
	if store == nil || peerID == "" {
		return
	}
	store.Update(peerID, now, func(snapshot *observability.PeerSnapshot) {
		if snapshot.DatagramStats == nil {
			snapshot.DatagramStats = &datagramStats{}
		}
		snapshot.DatagramStats.TooLargeDropped++
		snapshot.DatagramStats.LastTooLargeUnix = now.Unix()
		snapshot.DatagramStats.LastTooLargeDirection = direction
		snapshot.DatagramStats.LastTooLargeObject = object
		snapshot.DatagramStats.LastTooLargeZone = string(zoneName)
		snapshot.DatagramStats.LastTooLargeKey = key
		snapshot.DatagramStats.LastTooLargeBytes = size
		snapshot.DatagramStats.LastTooLargeLimit = limit
	})
}

func recordDatagramSendDiagnostics(store *observability.PeerObservabilityStore, peerID string, diag datagramSendDiagnostics, limit int, now time.Time) {
	if store == nil || peerID == "" {
		return
	}
	for _, oversized := range diag.Oversized {
		recordDatagramTooLarge(store, peerID, "send", oversized.Object, oversized.Zone, oversized.Key, oversized.Size, limit, now)
	}
	for i := 0; i < diag.ChunkFallbacks; i++ {
		recordDatagramChunkFallback(store, peerID, now)
	}
}

func recordDatagramChunkFallback(store *observability.PeerObservabilityStore, peerID string, now time.Time) {
	if store == nil || peerID == "" {
		return
	}
	store.Update(peerID, now, func(snapshot *observability.PeerSnapshot) {
		if snapshot.DatagramStats == nil {
			snapshot.DatagramStats = &datagramStats{}
		}
		snapshot.DatagramStats.ChunkFallbacks++
	})
}

func recordDatagramRepairNACK(store *observability.PeerObservabilityStore, peerID string, ignored bool, now time.Time) {
	if store == nil || peerID == "" {
		return
	}
	store.Update(peerID, now, func(snapshot *observability.PeerSnapshot) {
		if snapshot.DatagramStats == nil {
			snapshot.DatagramStats = &datagramStats{}
		}
		if ignored {
			snapshot.DatagramStats.ChunkRepairIgnored++
		} else {
			snapshot.DatagramStats.ChunkRepairNACKs++
		}
	})
}

func recordDatagramRepairSent(store *observability.PeerObservabilityStore, peerID string, chunks int, now time.Time) {
	if store == nil || peerID == "" || chunks <= 0 {
		return
	}
	store.Update(peerID, now, func(snapshot *observability.PeerSnapshot) {
		if snapshot.DatagramStats == nil {
			snapshot.DatagramStats = &datagramStats{}
		}
		snapshot.DatagramStats.ChunkRepairChunks += int64(chunks)
	})
}

func recordCatalogSummary(store *observability.PeerObservabilityStore, peerID string, summary *corestate.CatalogSummary, now time.Time) {
	if store == nil || peerID == "" || summary == nil {
		return
	}
	store.Update(peerID, now, func(snapshot *observability.PeerSnapshot) {
		if snapshot.DatagramStats == nil {
			snapshot.DatagramStats = &datagramStats{}
		}
		snapshot.DatagramStats.LastCatalogUnix = now.Unix()
		snapshot.DatagramStats.LastCatalogRootHex = hex.EncodeToString(summary.CatalogRoot)
		snapshot.DatagramStats.LastCatalogZoneCount = summary.ZoneCount
		snapshot.DatagramStats.LastCatalogCursor = summary.NextCursor
		if summary.FirstPage != nil {
			snapshot.DatagramStats.LastCatalogPageEntries = len(summary.FirstPage.Entries)
		}
		snapshot.DatagramStats.LastCatalogRejectedReason = ""
	})
}

func recordCatalogPage(store *observability.PeerObservabilityStore, peerID string, page *corestate.CatalogPage, now time.Time) {
	if store == nil || peerID == "" || page == nil {
		return
	}
	store.Update(peerID, now, func(snapshot *observability.PeerSnapshot) {
		if snapshot.DatagramStats == nil {
			snapshot.DatagramStats = &datagramStats{}
		}
		snapshot.DatagramStats.LastCatalogUnix = now.Unix()
		snapshot.DatagramStats.LastCatalogRootHex = hex.EncodeToString(page.CatalogRoot)
		snapshot.DatagramStats.LastCatalogCursor = page.NextCursor
		snapshot.DatagramStats.LastCatalogPageEntries = len(page.Entries)
		snapshot.DatagramStats.LastCatalogRejectedReason = ""
	})
}

func recordCatalogReject(store *observability.PeerObservabilityStore, peerID, cursor, reason string, now time.Time) {
	if store == nil || peerID == "" {
		return
	}
	store.Update(peerID, now, func(snapshot *observability.PeerSnapshot) {
		if snapshot.DatagramStats == nil {
			snapshot.DatagramStats = &datagramStats{}
		}
		snapshot.DatagramStats.LastCatalogUnix = now.Unix()
		snapshot.DatagramStats.LastCatalogCursor = cursor
		snapshot.DatagramStats.LastCatalogRejectedReason = reason
	})
}

func syncLimits(config *syncConfigFile) corestate.SyncLimits {
	limits := corestate.DefaultSyncLimits()
	if config == nil {
		return limits
	}
	if config.MaxSyncZones > 0 {
		limits.MaxZones = config.MaxSyncZones
	}
	if config.MaxSyncRecords > 0 {
		limits.MaxRecords = config.MaxSyncRecords
	}
	if config.MaxMessageBytes > 0 {
		limits.MaxBytes = config.MaxMessageBytes
	}
	return limits
}
