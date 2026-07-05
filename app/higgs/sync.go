package main

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"sync"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

const relayMinInterval = time.Second
const defaultSyncRoundTimeout = 5 * time.Second
const syncOnceResponderQuiet = 500 * time.Millisecond
const maxRelayFanoutPerUpdate = 8
const rejectedDigestTTL = 10 * time.Minute
const observedPathTTL = 3 * time.Minute
const observedPathMigrationGrace = time.Minute
const chunkAssemblyTTL = 2 * time.Minute
const maxChunkObjectBytes = 8 << 20

var collectSyncLocalEndpoints = gossip.CollectLocalEndpointsWithReflectors

var udpChunkAssemblies = newChunkAssemblyStore()

type chunkAssemblyStore struct {
	mu      sync.Mutex
	entries map[string]*chunkAssembly
}

type chunkAssembly struct {
	peerID     string
	object     gossip.ObjectPullRequestType
	zone       zone.ZonePath
	key        string
	version    uint64
	rootHash   []byte
	objectHash []byte
	total      uint16
	chunks     [][]byte
	received   int
	bytes      int
	created    time.Time
	updated    time.Time
}

type SyncRuntime struct {
	App           *Runtime
	State         *stateFile
	Config        *syncConfigFile
	Transport     *gossip.Transport
	TransportDeps *SyncTransportDeps
}

type SyncTransportDeps struct {
	KnownPeers map[string]*net.UDPAddr
	Replay     *gossip.ReplayWindow
	Quotas     *gossip.PeerQuotas
	Log        func(gossip.Event)
}

func newSyncRuntime(state *stateFile, config *syncConfigFile, transport *gossip.Transport, app *Runtime) *SyncRuntime {
	return &SyncRuntime{
		App:       app,
		State:     state,
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

func newChunkAssemblyStore() *chunkAssemblyStore {
	return &chunkAssemblyStore{entries: make(map[string]*chunkAssembly)}
}

func chunkAssemblyKey(peerID string, chunk *gossip.ObjectChunk) string {
	if chunk == nil {
		return ""
	}
	return peerID + "|" + string(chunk.Object) + "|" + chunk.Zone.String() + "|" + chunk.Key + "|" + strconv.FormatUint(chunk.Version, 10) + "|" + hex.EncodeToString(chunk.ObjectHash)
}

func (s *chunkAssemblyStore) add(peerID string, chunk *gossip.ObjectChunk, now time.Time) ([]byte, bool, error) {
	if s == nil || chunk == nil {
		return nil, false, errors.New("chunk assembly input is nil")
	}
	key := chunkAssemblyKey(peerID, chunk)
	if key == "" {
		return nil, false, errors.New("chunk assembly key is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	entry := s.entries[key]
	if entry == nil {
		entry = &chunkAssembly{
			peerID:     peerID,
			object:     chunk.Object,
			zone:       chunk.Zone,
			key:        chunk.Key,
			version:    chunk.Version,
			rootHash:   append([]byte(nil), chunk.RootHash...),
			objectHash: append([]byte(nil), chunk.ObjectHash...),
			total:      chunk.Total,
			chunks:     make([][]byte, chunk.Total),
			created:    now,
		}
		s.entries[key] = entry
	}
	if entry.total != chunk.Total || entry.object != chunk.Object || entry.zone != chunk.Zone || entry.key != chunk.Key || entry.version != chunk.Version || !bytes.Equal(entry.objectHash, chunk.ObjectHash) || !bytes.Equal(entry.rootHash, chunk.RootHash) {
		delete(s.entries, key)
		return nil, false, errors.New("chunk metadata changed during assembly")
	}
	if chunk.Index >= entry.total {
		return nil, false, errors.New("chunk index out of range")
	}
	if entry.chunks[chunk.Index] == nil {
		entry.chunks[chunk.Index] = append([]byte(nil), chunk.Data...)
		entry.received++
		entry.bytes += len(chunk.Data)
		if entry.bytes > maxChunkObjectBytes {
			delete(s.entries, key)
			return nil, false, fmt.Errorf("chunk object exceeds max %d bytes", maxChunkObjectBytes)
		}
	}
	entry.updated = now
	if entry.received != int(entry.total) {
		return nil, false, nil
	}
	data := make([]byte, 0, entry.bytes)
	for _, part := range entry.chunks {
		if part == nil {
			return nil, false, nil
		}
		data = append(data, part...)
	}
	hash := sha256.Sum256(data)
	if !bytes.Equal(hash[:], entry.objectHash) {
		delete(s.entries, key)
		return nil, false, errors.New("chunk object hash mismatch")
	}
	delete(s.entries, key)
	return data, true, nil
}

func (s *chunkAssemblyStore) pruneLocked(now time.Time) {
	for key, entry := range s.entries {
		if entry == nil || now.Sub(entry.updated) > chunkAssemblyTTL && now.Sub(entry.created) > chunkAssemblyTTL {
			delete(s.entries, key)
		}
	}
}

// saveState persists the current state. The caller must hold the write lock
// on sr.State; saveState reads the state without acquiring its own lock.
func (sr *SyncRuntime) saveState() error {
	if sr != nil && sr.App != nil {
		return sr.App.SaveState(sr.State)
	}
	return saveState(sr.State)
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
	fmt.Fprintf(w, "peer_id: %s\n", config.PeerID)
	fmt.Fprintf(w, "listen_addr: %s\n", config.ListenAddr)
	digests := gossip.ZoneDigests(state.Network)
	fmt.Fprintf(w, "known_peers: %d\n", len(config.Bootstrap))
	fmt.Fprintf(w, "known_zones: %d\n", len(digests))
	fmt.Fprintf(w, "local_root: %s\n", hex.EncodeToString(globalRootHash(digests)))
	fmt.Fprintf(w, "limits: max_datagram_bytes=%d max_sync_zones=%d max_sync_records=%d wire_version=%d wire_codec=msgpack\n",
		config.MaxMessageBytes,
		config.MaxSyncZones,
		config.MaxSyncRecords,
		gossip.WireVersion,
	)
	discovered := gossip.ExtractPeerEndpoints(state.Network)
	if verbose {
		known := configuredKnownPeers(config)
		fmt.Fprintf(w, "allowlist_source: bootstrap+discovery\n")
		fmt.Fprintf(w, "bootstrap_peers: %d\n", len(config.Bootstrap))
		var discoveredCount int
		for peerID := range discovered {
			if !isBootstrapPeer(config, peerID) {
				discoveredCount++
			}
		}
		fmt.Fprintf(w, "discovered_peers: %d\n", discoveredCount)
		for _, peer := range config.Bootstrap {
			resolved := "-"
			if addr := known[peer.ID]; addr != nil {
				resolved = addr.String()
			}
			peerState := state.SyncPeers[peer.ID]
			fmt.Fprintf(w, "bootstrap peer=%s configured_addr=%s resolved_addr=%s status=%s last_success=%s last_error=%s next_retry=%s\n",
				peer.ID,
				peer.Addr,
				resolved,
				peerStatus(peerState, now),
				formatLastSuccess(peerState),
				dash(peerState.LastError),
				formatNextRetry(peerState, now),
			)
			fmt.Fprintf(w, "  update_source=%s last_relay=%s relay_suppression=%s\n",
				dash(peerState.LastUpdateSource),
				formatUnixTime(peerState.LastRelayUnix),
				formatRelaySuppression(peerState),
			)
			fmt.Fprintf(w, "  observed_addr=%s observed_status=%s\n",
				dash(peerState.ObservedAddr),
				formatObservedPath(peerState, now),
			)
			writeSyncFlow(w, peer.ID, peerState)
			writeDatagramStats(w, peer.ID, peerState)
			writeObjectPullStats(w, peer.ID, peerState)
		}
		for peerID, entries := range discovered {
			if isBootstrapPeer(config, peerID) {
				continue
			}
			peerState := state.SyncPeers[peerID]
			addr := "-"
			if len(entries) > 0 {
				addr = fmt.Sprintf("%s:%d", entries[0].Address, entries[0].Port)
			}
			fmt.Fprintf(w, "discovered peer=%s addr=%s status=%s last_success=%s\n",
				peerID,
				addr,
				peerStatus(peerState, now),
				formatLastSuccess(peerState),
			)
			fmt.Fprintf(w, "  observed_addr=%s observed_status=%s\n",
				dash(peerState.ObservedAddr),
				formatObservedPath(peerState, now),
			)
			writeSyncFlow(w, peerID, peerState)
			writeDatagramStats(w, peerID, peerState)
			writeObjectPullStats(w, peerID, peerState)
		}
	}
	for _, peer := range config.Bootstrap {
		peerState := state.SyncPeers[peer.ID]
		lastSync := "never"
		if peerState.LastSyncUnix != 0 {
			lastSync = time.Unix(peerState.LastSyncUnix, 0).UTC().Format(time.RFC3339)
		}
		lastError := peerState.LastError
		if lastError == "" {
			lastError = "-"
		}
		fmt.Fprintf(w, "peer %s addr=%s status=%s last_sync=%s known_zones=%d last_error=%s next_retry=%s\n",
			peer.ID,
			peer.Addr,
			peerStatus(peerState, now),
			lastSync,
			len(digests),
			lastError,
			formatNextRetry(peerState, now),
		)
	}
	for _, digest := range digests {
		zs := state.Network.Zones[digest.Zone]
		fmt.Fprintf(w, "zone %s root=%s records=%d history=%d delegations=%d revocations=%d\n",
			digest.Zone,
			hex.EncodeToString(digest.RootHash),
			len(zs.Records),
			countHistory(zs),
			len(zs.Delegations),
			len(zs.Revocations),
		)
	}
	return nil
}

func writeDatagramStats(w io.Writer, peerID string, peerState syncPeerState) {
	stats := peerState.DatagramStats
	if stats == nil || (stats.TooLargeDropped == 0 && stats.DigestOnlyAnnounces == 0 && stats.ChunkFallbacks == 0 && stats.LastCatalogUnix == 0 && stats.LastCatalogRejectedReason == "") {
		return
	}
	if stats.LastCatalogUnix != 0 || stats.LastCatalogRejectedReason != "" {
		lastCatalog := "-"
		if stats.LastCatalogUnix != 0 {
			lastCatalog = time.Unix(stats.LastCatalogUnix, 0).UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "catalog peer=%s root=%s zone_count=%d cursor=%s page_entries=%d last=%s rejected_reason=%s\n",
			peerID,
			dash(stats.LastCatalogRootHex),
			stats.LastCatalogZoneCount,
			dash(stats.LastCatalogCursor),
			stats.LastCatalogPageEntries,
			lastCatalog,
			dash(stats.LastCatalogRejectedReason),
		)
	}
	last := "-"
	if stats.LastTooLargeUnix != 0 {
		last = time.Unix(stats.LastTooLargeUnix, 0).UTC().Format(time.RFC3339)
	}
	fmt.Fprintf(w, "datagram peer=%s too_large_dropped=%d digest_only_announces=%d chunk_fallbacks=%d last_too_large=%s direction=%s object=%s zone=%s key=%s bytes=%d limit=%d\n",
		peerID,
		stats.TooLargeDropped,
		stats.DigestOnlyAnnounces,
		stats.ChunkFallbacks,
		last,
		dash(stats.LastTooLargeDirection),
		dash(stats.LastTooLargeObject),
		dash(stats.LastTooLargeZone),
		dash(stats.LastTooLargeKey),
		stats.LastTooLargeBytes,
		stats.LastTooLargeLimit,
	)
}

func writeSyncFlow(w io.Writer, peerID string, peerState syncPeerState) {
	if peerState.ActivePullState == "" &&
		peerState.HintAccepted == 0 &&
		peerState.HintSuppressed == 0 &&
		peerState.ReadOnlyResponder == 0 {
		return
	}
	fmt.Fprintf(w, "sync_flow peer=%s active_pull=%s active_event=%s active_updated=%s hint_accepted=%d hint_suppressed=%d last_hint=%s hint_reason=%s hint_suppression=%s read_only_responder=%d responder_kind=%s responder_zone=%s responder_last=%s\n",
		peerID,
		dash(peerState.ActivePullState),
		dash(peerState.ActivePullLastEvent),
		formatUnixTime(peerState.ActivePullUpdatedUnix),
		peerState.HintAccepted,
		peerState.HintSuppressed,
		formatUnixTime(peerState.LastHintUnix),
		dash(peerState.LastHintReason),
		dash(peerState.LastHintSuppression),
		peerState.ReadOnlyResponder,
		dash(peerState.LastResponderKind),
		dash(peerState.LastResponderZone),
		formatUnixTime(peerState.LastResponderUnix),
	)
}

func writeObjectPullStats(w io.Writer, peerID string, peerState syncPeerState) {
	stats := peerState.ObjectPullStats
	if stats == nil || (stats.Attempts == 0 && stats.Successes == 0 && stats.Failures == 0 && stats.LargeObjectUnreachable == 0) {
		return
	}
	last := "-"
	if stats.LastUnix != 0 {
		last = time.Unix(stats.LastUnix, 0).UTC().Format(time.RFC3339)
	}
	fmt.Fprintf(w, "object_pull peer=%s attempts=%d successes=%d failures=%d large_object_unreachable=%d last=%s object=%s zone=%s key=%s bytes=%d source_peer=%s unreachable=%t last_error=%s\n",
		peerID,
		stats.Attempts,
		stats.Successes,
		stats.Failures,
		stats.LargeObjectUnreachable,
		last,
		dash(stats.LastObject),
		dash(stats.LastZone),
		dash(stats.LastKey),
		stats.LastBytes,
		dash(stats.LastSourcePeer),
		stats.LastUnreachable,
		dash(stats.LastError),
	)
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
	transport, err := service.Sync.openTransport()
	if err != nil {
		return err
	}
	packetCh, stopRecv := startGossipPacketReceiver(ctx, transport, logger.Warn)
	defer stopRecv()
	service.Sync.Transport = transport
	objectPullListener, err := objectPullTCPServe(objectPullTCPAddr(transport.LocalAddr().String()), objectPullLookup(func() *stateFile {
		state, _, _ := service.snapshotState()
		return state
	}))
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
		case event := <-service.syncEvents:
			service.handleSyncEvent(ctx, event)
		case result := <-service.objectPullResults:
			service.commitObjectPullResult(result)
			service.enqueueObjectPullResult(result)
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
	transport, err := service.Sync.openTransport()
	if err != nil {
		return err
	}
	defer transport.Close()
	service.Sync.Transport = transport
	objectPullListener, err := objectPullTCPServe(objectPullTCPAddr(transport.LocalAddr().String()), objectPullLookup(func() *stateFile {
		state, _, _ := service.snapshotState()
		return state
	}))
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
	service.Sync.updateDiscoveredPeers()
	if err := service.startHintedSyncSession(peerID, "sync_once"); err != nil {
		return err
	}
	var responderQuietUntil time.Time
	for {
		drained := false
		if _, ok := service.syncSessions[peerID]; !ok && len(service.syncEvents) == 0 && len(service.objectPullResults) == 0 {
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
			if session := service.syncSessions[peerID]; session != nil && len(session.pendingZones) > 0 {
				pending := make([]zone.ZonePath, 0, len(session.pendingZones))
				for path := range session.pendingZones {
					pending = append(pending, path)
				}
				return &syncPendingZonesError{zones: pending}
			}
			return errors.New("sync receive timed out")
		case event := <-service.syncEvents:
			responderQuietUntil = time.Time{}
			service.handleSyncEvent(ctx, event)
		case result := <-service.objectPullResults:
			responderQuietUntil = time.Time{}
			service.commitObjectPullResult(result)
			service.enqueueObjectPullResult(result)
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

func (sr *SyncRuntime) reloadStateIfChanged(previous []gossip.ZoneDigest) (*stateFile, bool, error) {
	latest, err := sr.loadState()
	if err != nil {
		return nil, false, err
	}
	if !sameZoneDigests(previous, gossip.ZoneDigests(latest.Network)) {
		return latest, true, nil
	}
	return latest, false, nil
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

func sameZoneDigests(a, b []gossip.ZoneDigest) bool {
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

func fetchListForPeer(state *stateFile, peerID string, remote []gossip.ZoneDigest, now time.Time) []zone.ZonePath {
	if state == nil {
		return nil
	}
	fetch := gossip.FetchList(state.Network, remote)
	if len(fetch) == 0 || peerID == "" {
		return fetch
	}
	remoteByZone := make(map[zone.ZonePath][]byte, len(remote))
	for _, digest := range remote {
		remoteByZone[digest.Zone] = digest.RootHash
	}
	out := fetch[:0]
	for _, path := range fetch {
		if shouldSkipRemoteZone(state, peerID, path, remoteByZone[path], now) {
			continue
		}
		out = append(out, path)
	}
	return out
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
func recordRejectedDigest(state *stateFile, peerID string, digest gossip.ZoneDigest, reason string, now time.Time) {
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

func isRejectedRecordActive(state *stateFile, peerID string, record *gossip.RecordSnapshot, reason string, now time.Time) bool {
	if state == nil || peerID == "" || record == nil || record.Record == nil {
		return false
	}
	peerState := state.SyncPeers[peerID]
	rejected, ok := peerState.RejectedDigests[rejectedRecordKey(record.Zone, record.Record.Key)]
	if !ok {
		return false
	}
	if rejected.Object != "record" {
		return false
	}
	if reason != "" && rejected.Reason != normalizedRejectReason(reason) {
		return false
	}
	if rejected.ObjectHashHex != hex.EncodeToString(recordObjectHash(record.Record)) {
		return false
	}
	return rejected.UntilUnix != 0 && now.Before(time.Unix(rejected.UntilUnix, 0))
}

// recordRejectedRecord mutates state.SyncPeers. The caller must hold the write
// lock on state.
func recordRejectedRecord(state *stateFile, peerID string, record *gossip.RecordSnapshot, reason string, now time.Time) {
	if state == nil || peerID == "" || record == nil || record.Record == nil || !record.Zone.Valid() {
		return
	}
	reason = normalizedRejectReason(reason)
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	if peerState.RejectedDigests == nil {
		peerState.RejectedDigests = make(map[string]rejectedDigestState)
	}
	peerState.RejectedDigests[rejectedRecordKey(record.Zone, record.Record.Key)] = rejectedDigestState{
		Zone:           record.Zone,
		Object:         "record",
		Key:            record.Record.Key,
		ObjectHashHex:  hex.EncodeToString(recordObjectHash(record.Record)),
		Reason:         reason,
		RejectedAtUnix: now.Unix(),
		UntilUnix:      now.Add(rejectedDigestTTL).Unix(),
	}
	state.SyncPeers[peerID] = peerState
}

func recordObjectHash(record *zone.Record) []byte {
	if record == nil {
		return nil
	}
	data, err := json.Marshal(record)
	if err != nil {
		return higgscrypto.RecordHash(record)
	}
	return higgscrypto.Hash(data)
}

func normalizedRejectReason(reason string) string {
	if reason == "" {
		return "verify_failed"
	}
	return reason
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

func rejectedRecordKey(path zone.ZonePath, key string) string {
	return "record:" + path.String() + ":" + key
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

// recordObservedPathFailure mutates state.SyncPeers. The caller must hold the
// write lock on state.
func recordObservedPathFailure(state *stateFile, peerID string) {
	if state == nil || peerID == "" {
		return
	}
	peerState := state.SyncPeers[peerID]
	if peerState.ObservedAddr == "" {
		return
	}
	peerState.ObservedFailureCount++
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
	configureValidation(state.Network)
	return higgscrypto.VerifyChain(state.Network, path, now) == nil
}

// seedObservedPeerPaths mutates transport observed paths based on state.SyncPeers.
// The caller must hold the appropriate lock on sr.State.
func (sr *SyncRuntime) seedObservedPeerPaths() {
	if sr == nil || sr.State == nil || sr.Transport == nil {
		return
	}
	now := sr.now()
	for peerID := range sr.State.SyncPeers {
		sr.seedObservedPeerPathAt(peerID, now)
	}
}

func (sr *SyncRuntime) seedObservedPeerPath(peerID string) {
	if sr == nil {
		return
	}
	sr.seedObservedPeerPathAt(peerID, sr.now())
}

func (sr *SyncRuntime) seedObservedPeerPathAt(peerID string, now time.Time) {
	if sr == nil || sr.State == nil || sr.Transport == nil || peerID == "" {
		return
	}
	peerState := sr.State.SyncPeers[peerID]
	if !observedPathActive(peerState, now) || !peerChainVerified(sr.State, peerID, now) {
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

func openSyncTransport(config *syncConfigFile, state *stateFile) (*gossip.Transport, error) {
	return newSyncRuntime(state, config, nil, nil).openTransport()
}

func (sr *SyncRuntime) openTransport() (*gossip.Transport, error) {
	deps := sr.syncTransportDeps()
	transport, err := gossip.Listen(sr.transportConfig(deps))
	if err != nil {
		return nil, err
	}
	sr.Transport = transport
	sr.seedTransportPeers(deps)
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

func (sr *SyncRuntime) seedTransportPeers(deps *SyncTransportDeps) {
	if sr.State == nil || sr.Transport == nil {
		return
	}
	addVerifiedZonePeers(sr.State, sr.Transport, sr.Config)
	sr.seedObservedPeerPaths()
	for peerID, entries := range gossip.ExtractPeerEndpoints(sr.State.Network) {
		if peerID == sr.Config.PeerID || peerID == string(sr.State.ManagedZone) {
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

func (sr *SyncRuntime) publishEndpointRecord() error {
	changed, err := sr.publishEndpointRecordInState(sr.State)
	if err != nil || !changed {
		return err
	}
	return sr.saveState()
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

func (sr *SyncRuntime) tryAdoptAutoJoinAfterSync(peerID, via string) bool {
	adopted, err := tryAdoptAutoJoinDelegation(sr.State, sr.now())
	recordAdoptionResult(sr.State, adopted, err, sr.now())
	if err != nil {
		sr.logger().Warn("auto_join", "adopt_failed", map[string]any{
			"peer_id": peerID,
			"zone":    sr.State.ManagedZone,
			"via":     via,
			"error":   err,
		})
		return false
	}
	if !adopted {
		recordBootstrapSyncSuccess(sr.State, peerID, sr.Config, sr.now())
		return false
	}
	sr.logger().Info("auto_join", "adopted", map[string]any{
		"peer_id": peerID,
		"zone":    sr.State.ManagedZone,
		"via":     via,
	})
	return true
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
	newSyncRuntime(state, config, transport, nil).addVerifiedZonePeers()
}

// addVerifiedZonePeers mutates transport known-peer state based on state.Network.
// The caller must hold the appropriate lock on sr.State.
func (sr *SyncRuntime) addVerifiedZonePeers() {
	state := sr.State
	transport := sr.Transport
	config := sr.Config
	if state == nil || state.Network == nil {
		return
	}
	configureValidation(state.Network)
	now := sr.now()
	for path := range state.Network.Zones {
		peerID := string(path)
		if peerID == config.PeerID || peerID == string(state.ManagedZone) {
			continue
		}
		if err := higgscrypto.VerifyChain(state.Network, path, now); err != nil {
			continue
		}
		transport.AddKnownPeerID(peerID)
	}
	for parentPath, zs := range state.Network.Zones {
		if zs == nil || len(zs.Delegations) == 0 {
			continue
		}
		if err := higgscrypto.VerifyChain(state.Network, parentPath, now); err != nil {
			continue
		}
		for childPath := range zs.Delegations {
			peerID := string(childPath)
			if peerID == config.PeerID || peerID == string(state.ManagedZone) || state.Network.IsZoneRevoked(childPath, now) {
				continue
			}
			transport.AddKnownPeerID(peerID)
		}
	}
}

// updateDiscoveredPeers mutates state.SyncPeers and transport peer addresses.
// The caller must hold the write lock on state.
func updateDiscoveredPeers(state *stateFile, transport *gossip.Transport, config *syncConfigFile) {
	newSyncRuntime(state, config, transport, nil).updateDiscoveredPeers()
}

// updateDiscoveredPeers mutates state.SyncPeers and transport peer addresses.
// The caller must hold the write lock on sr.State.
func (sr *SyncRuntime) updateDiscoveredPeers() {
	state := sr.State
	transport := sr.Transport
	config := sr.Config
	sr.addVerifiedZonePeers()
	now := sr.now()
	discovered := gossip.ExtractPeerEndpointsAt(state.Network, now)
	bootstrapPeers := configuredKnownPeers(config)
	updated := false
	activeDiscovered := make(map[string]bool)
	sr.seedObservedPeerPaths()
	for peerID, entries := range discovered {
		if peerID == config.PeerID || peerID == string(state.ManagedZone) {
			continue
		}
		if len(entries) == 0 {
			continue
		}
		addrs := buildPeerAddrs(peerID, entries, bootstrapPeers[peerID], state.SyncPeers[peerID], config.EndpointGrace, config.EndpointSourceOrder, now)
		if len(addrs) == 0 {
			continue
		}
		activeDiscovered[peerID] = true
		transport.SetPeerAddrs(peerID, addrs)
		normalizeSyncPeers(state)
		ps := state.SyncPeers[peerID]
		ps.DiscoveredAddr = addrs[0].String()
		ps.DiscoveredAtUnix = now.Unix()
		state.SyncPeers[peerID] = ps
		updated = true
	}
	for peerID, peerState := range state.SyncPeers {
		if peerState.ObservedAddr != "" && !observedPathActive(peerState, now) {
			if transport != nil {
				transport.RemoveObservedPeerAddr(peerID)
			}
			peerState.ObservedAddr = ""
			peerState.ObservedFirstSeenUnix = 0
			peerState.ObservedLastSeenUnix = 0
			peerState.ObservedLastSyncUnix = 0
			peerState.ObservedUntilUnix = 0
			peerState.ObservedSource = ""
			peerState.ObservedFailureCount = 0
			state.SyncPeers[peerID] = peerState
			updated = true
		}
		if peerState.DiscoveredAddr == "" || activeDiscovered[peerID] || isBootstrapPeer(config, peerID) {
			continue
		}
		if peerID == config.PeerID || peerID == string(state.ManagedZone) {
			continue
		}
		if len(discovered[peerID]) > 0 {
			continue
		}
		if len(appendRecentSuccessfulDiscoveredAddr(nil, peerState, config.EndpointGrace, now)) > 0 {
			continue
		}
		transport.RemovePeerAddrs(peerID)
		peerState.DiscoveredAddr = ""
		peerState.DiscoveredAtUnix = 0
		state.SyncPeers[peerID] = peerState
		updated = true
	}
	if updated {
		if err := sr.saveState(); err != nil {
			sr.logger().Warn("endpoint", "discovered_peer_save_failed", map[string]any{"error": err})
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

func (sr *SyncRuntime) handleObjectChunk(message *gossip.Message, limits gossip.SyncLimits) error {
	if sr == nil || message == nil || message.ObjectChunk == nil {
		return nil
	}
	chunk := message.ObjectChunk
	data, complete, err := udpChunkAssemblies.add(message.PeerID, chunk, sr.now())
	if err != nil {
		if chunk.Object == gossip.ObjectPullZone {
			recordRejectedDigest(sr.State, message.PeerID, gossip.ZoneDigest{Zone: chunk.Zone, RootHash: chunk.RootHash}, gossip.RejectReason(err), sr.now())
		}
		return err
	}
	if !complete {
		return nil
	}
	switch chunk.Object {
	case gossip.ObjectPullZone:
		snapshot, err := gossip.DecodeZoneSnapshotObject(data)
		if err != nil {
			recordRejectedDigest(sr.State, message.PeerID, gossip.ZoneDigest{Zone: chunk.Zone, RootHash: chunk.RootHash}, gossip.RejectReason(err), sr.now())
			return err
		}
		pullLimits := limits
		pullLimits.MaxBytes = maxChunkObjectBytes
		result, err := gossip.ApplySnapshot(sr.State.Network, snapshot, sr.now(), pullLimits)
		if err != nil {
			recordRejectedDigest(sr.State, message.PeerID, gossip.ZoneDigest{Zone: chunk.Zone, RootHash: chunk.RootHash}, gossip.RejectReason(err), sr.now())
			return err
		}
		clearRejectedDigest(sr.State, message.PeerID, chunk.Zone)
		recordDatagramChunkFallback(sr.State, message.PeerID)
		sr.tryAdoptAutoJoinAfterSync(message.PeerID, "udp_chunks")
		sr.logger().Info("sync", "zone_applied", map[string]any{
			"peer_id":     message.PeerID,
			"zone":        result.Zone,
			"records":     result.Records,
			"delegations": result.Delegation,
			"via":         "udp_chunks",
		})
		return sr.saveState()
	default:
		return nil
	}
}

// sendSnapshots sends bounded zone digest hints. When allowChunks is true, it
// also sends full zone snapshots as UDP object chunks for explicit fallback
// requests. Ordinary ANNOUNCE no longer carries snapshot or record payloads.
func sendSnapshots(ns *zone.NetworkState, transport *gossip.Transport, peerID string, zones []zone.ZonePath) error {
	return sendSnapshotsWithStats(nil, ns, transport, peerID, zones, time.Now(), false, nil)
}

func (sr *SyncRuntime) sendSnapshots(peerID string, zones []zone.ZonePath, allowChunks bool) error {
	if sr == nil {
		return nil
	}
	return sendSnapshotsWithStats(sr.State, sr.State.Network, sr.Transport, peerID, zones, sr.now(), allowChunks, sr.logger())
}

func sendSnapshotsWithStats(state *stateFile, ns *zone.NetworkState, transport *gossip.Transport, peerID string, zones []zone.ZonePath, now time.Time, allowChunks bool, logger *appLogger) error {
	diag, err := sendSnapshotsWithDiagnostics(ns, transport, peerID, zones, now, allowChunks, logger)
	recordDatagramSendDiagnostics(state, peerID, diag, transport.MaxMessageBytes(), now)
	return err
}

type datagramSendDiagnostics struct {
	Oversized      []oversizedDatagramObject
	ChunkFallbacks int
}

func sendSnapshotsWithDiagnostics(ns *zone.NetworkState, transport *gossip.Transport, peerID string, zones []zone.ZonePath, now time.Time, allowChunks bool, logger *appLogger) (datagramSendDiagnostics, error) {
	var diag datagramSendDiagnostics
	plan := planSnapshotDatagrams(ns, zones, transport.MaxMessageBytes(), now)
	chunkZones := make(map[zone.ZonePath]bool)
	if allowChunks && ns != nil {
		for _, path := range zones {
			if zs := ns.Zones[path]; zs != nil && !ns.IsZoneRevoked(path, now) {
				chunkZones[path] = true
			}
		}
	}
	for _, oversized := range plan.Oversized {
		diag.Oversized = append(diag.Oversized, oversized)
		if logger != nil && logger.debugEnabled() {
			logger.Debug("transport", "datagram_too_large", map[string]any{
				"peer_id": peerID,
				"object":  oversized.Object,
				"zone":    oversized.Zone,
				"key":     oversized.Key,
				"bytes":   oversized.Size,
				"limit":   transport.MaxMessageBytes(),
				"action":  "skip_udp",
			})
		}
	}
	for _, announce := range plan.Announces {
		msg := &gossip.Message{Type: gossip.MessageAnnounce, Announce: announce}
		if err := transport.Send(peerID, msg); err != nil {
			return diag, err
		}
	}
	for path := range chunkZones {
		chunks, err := sendZoneSnapshotChunks(ns, transport, peerID, path, now)
		diag.ChunkFallbacks += chunks
		if err != nil {
			return diag, err
		}
	}
	return diag, nil
}

func sendZoneSnapshotChunks(ns *zone.NetworkState, transport *gossip.Transport, peerID string, path zone.ZonePath, now time.Time) (int, error) {
	if ns == nil || transport == nil || ns.IsZoneRevoked(path, now) {
		return 0, nil
	}
	zs := ns.Zones[path]
	if zs == nil {
		return 0, nil
	}
	snapshot, err := gossip.Snapshot(ns, path)
	if err != nil {
		return 0, nil
	}
	data, err := gossip.EncodeZoneSnapshotObject(snapshot)
	if err != nil {
		return 0, err
	}
	if len(data) > maxChunkObjectBytes {
		return 0, fmt.Errorf("chunk zone snapshot %s exceeds max %d bytes", path, maxChunkObjectBytes)
	}
	chunkSize := maxObjectChunkDataSize(transport.MaxMessageBytes(), peerID, path)
	if chunkSize <= 0 {
		return 0, gossip.ErrMessageTooLarge
	}
	total := (len(data) + chunkSize - 1) / chunkSize
	if total <= 0 || total > int(^uint16(0)) {
		return 0, fmt.Errorf("chunk zone snapshot %s needs invalid chunk count %d", path, total)
	}
	objectHash := sha256.Sum256(data)
	rootHash := gossip.ZoneRoot(zs)
	sent := 0
	for i := 0; i < total; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		msg := &gossip.Message{
			Type: gossip.MessageObjectChunk,
			ObjectChunk: &gossip.ObjectChunk{
				Object:     gossip.ObjectPullZone,
				Zone:       path,
				RootHash:   append([]byte(nil), rootHash...),
				ObjectHash: append([]byte(nil), objectHash[:]...),
				Index:      uint16(i),
				Total:      uint16(total),
				Data:       data[start:end],
			},
		}
		if err := transport.Send(peerID, msg); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func maxObjectChunkDataSize(budget int, peerID string, path zone.ZonePath) int {
	if budget <= 0 {
		return 0
	}
	low, high := 1, budget
	best := 0
	for low <= high {
		mid := (low + high) / 2
		data, err := gossip.MarshalMessage(&gossip.Message{
			Type:      gossip.MessageObjectChunk,
			PeerID:    peerID,
			Nonce:     1,
			Timestamp: 1,
			ObjectChunk: &gossip.ObjectChunk{
				Object:     gossip.ObjectPullZone,
				Zone:       path,
				RootHash:   make([]byte, 32),
				ObjectHash: make([]byte, 32),
				Total:      1,
				Data:       make([]byte, mid),
			},
		})
		if err == nil && len(data) <= budget {
			best = mid
			low = mid + 1
			continue
		}
		high = mid - 1
	}
	return best
}

type snapshotDatagramPlan struct {
	Announces []*gossip.Announce
	Oversized []oversizedDatagramObject
}

type oversizedDatagramObject struct {
	Object string
	Zone   zone.ZonePath
	Key    string
	Size   int
}

func planSnapshotDatagrams(ns *zone.NetworkState, zones []zone.ZonePath, budget int, now time.Time) snapshotDatagramPlan {
	if ns == nil || budget <= 0 {
		return snapshotDatagramPlan{}
	}
	zones = append([]zone.ZonePath(nil), zones...)
	sort.Slice(zones, func(i, j int) bool { return zones[i] < zones[j] })

	var digests []gossip.ZoneDigest
	var oversized []oversizedDatagramObject

	for _, path := range zones {
		zs := ns.Zones[path]
		if zs == nil || ns.IsZoneRevoked(path, now) {
			continue
		}
		digest := gossip.ZoneDigest{Zone: path, RootHash: gossip.ZoneRoot(zs)}
		digestSize := announceWireSize(&gossip.Announce{Zones: []gossip.ZoneDigest{digest}})
		if digestSize > budget {
			oversized = append(oversized, oversizedDatagramObject{Object: "announce_digest", Zone: path, Size: digestSize})
			continue
		}
		digests = append(digests, digest)
	}

	var announces []*gossip.Announce
	announces = append(announces, packDigestAnnounces(digests, budget)...)
	return snapshotDatagramPlan{Announces: announces, Oversized: oversized}
}

func packDigestAnnounces(digests []gossip.ZoneDigest, budget int) []*gossip.Announce {
	var out []*gossip.Announce
	var current []gossip.ZoneDigest
	for _, digest := range digests {
		next := append(append([]gossip.ZoneDigest(nil), current...), digest)
		if len(current) == 0 && announceWireSize(&gossip.Announce{Zones: next}) > budget {
			continue
		}
		if len(current) > 0 && announceWireSize(&gossip.Announce{Zones: next}) > budget {
			out = append(out, &gossip.Announce{Zones: current})
			current = []gossip.ZoneDigest{digest}
			continue
		}
		current = next
	}
	if len(current) > 0 {
		out = append(out, &gossip.Announce{Zones: current})
	}
	return out
}

func announceWireSize(announce *gossip.Announce) int {
	size, err := gossip.WireEncodeSize(&gossip.Message{Type: gossip.MessageAnnounce, Announce: announce})
	if err != nil {
		return 1 << 30
	}
	return size
}

func snapshotRecordMessages(snapshot *gossip.ZoneSnapshot) []gossip.RecordSnapshot {
	if snapshot == nil {
		return nil
	}
	type keyedRecord struct {
		key    string
		record *zone.Record
		active bool
	}
	var records []keyedRecord
	for key, record := range snapshot.Records {
		if record != nil {
			records = append(records, keyedRecord{key: key, record: record, active: true})
		}
	}
	for key, history := range snapshot.RecordHistory {
		for _, record := range history {
			if record != nil {
				records = append(records, keyedRecord{key: key, record: record})
			}
		}
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].key != records[j].key {
			return records[i].key < records[j].key
		}
		if records[i].active != records[j].active {
			return records[i].active
		}
		if records[i].record.Version != records[j].record.Version {
			return records[i].record.Version < records[j].record.Version
		}
		return bytes.Compare(higgscrypto.RecordHash(records[i].record), higgscrypto.RecordHash(records[j].record)) < 0
	})
	out := make([]gossip.RecordSnapshot, 0, len(records))
	for _, item := range records {
		out = append(out, gossip.RecordSnapshot{
			Zone:   snapshot.Zone,
			Record: item.record,
		})
	}
	return out
}

func messageWireSize(msg *gossip.Message) int {
	size, err := gossip.WireEncodeSize(msg)
	if err != nil {
		return 1 << 30
	}
	return size
}

// recordDatagramTooLarge mutates state.SyncPeers. The caller must hold the write
// lock on state.
func recordDatagramTooLarge(state *stateFile, peerID, direction, object string, zoneName zone.ZonePath, key string, size, limit int, now time.Time) {
	if state == nil || peerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	if peerState.DatagramStats == nil {
		peerState.DatagramStats = &datagramStats{}
	}
	peerState.DatagramStats.TooLargeDropped++
	peerState.DatagramStats.LastTooLargeUnix = now.Unix()
	peerState.DatagramStats.LastTooLargeDirection = direction
	peerState.DatagramStats.LastTooLargeObject = object
	peerState.DatagramStats.LastTooLargeZone = string(zoneName)
	peerState.DatagramStats.LastTooLargeKey = key
	peerState.DatagramStats.LastTooLargeBytes = size
	peerState.DatagramStats.LastTooLargeLimit = limit
	state.SyncPeers[peerID] = peerState
}

func recordDatagramSendDiagnostics(state *stateFile, peerID string, diag datagramSendDiagnostics, limit int, now time.Time) {
	if state == nil || peerID == "" {
		return
	}
	for _, oversized := range diag.Oversized {
		recordDatagramTooLarge(state, peerID, "send", oversized.Object, oversized.Zone, oversized.Key, oversized.Size, limit, now)
	}
	for i := 0; i < diag.ChunkFallbacks; i++ {
		recordDatagramChunkFallback(state, peerID)
	}
}

// recordDatagramChunkFallback mutates state.SyncPeers. The caller must hold the
// write lock on state.
func recordDatagramChunkFallback(state *stateFile, peerID string) {
	if state == nil || peerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	if peerState.DatagramStats == nil {
		peerState.DatagramStats = &datagramStats{}
	}
	peerState.DatagramStats.ChunkFallbacks++
	state.SyncPeers[peerID] = peerState
}

func recordCatalogSummary(state *stateFile, peerID string, summary *gossip.CatalogSummary, now time.Time) {
	if state == nil || peerID == "" || summary == nil {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	if peerState.DatagramStats == nil {
		peerState.DatagramStats = &datagramStats{}
	}
	peerState.DatagramStats.LastCatalogUnix = now.Unix()
	peerState.DatagramStats.LastCatalogRootHex = hex.EncodeToString(summary.CatalogRoot)
	peerState.DatagramStats.LastCatalogZoneCount = summary.ZoneCount
	peerState.DatagramStats.LastCatalogCursor = summary.NextCursor
	if summary.FirstPage != nil {
		peerState.DatagramStats.LastCatalogPageEntries = len(summary.FirstPage.Entries)
	}
	peerState.DatagramStats.LastCatalogRejectedReason = ""
	state.SyncPeers[peerID] = peerState
}

func recordCatalogPage(state *stateFile, peerID string, page *gossip.CatalogPage, now time.Time) {
	if state == nil || peerID == "" || page == nil {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	if peerState.DatagramStats == nil {
		peerState.DatagramStats = &datagramStats{}
	}
	peerState.DatagramStats.LastCatalogUnix = now.Unix()
	peerState.DatagramStats.LastCatalogRootHex = hex.EncodeToString(page.CatalogRoot)
	peerState.DatagramStats.LastCatalogCursor = page.NextCursor
	peerState.DatagramStats.LastCatalogPageEntries = len(page.Entries)
	peerState.DatagramStats.LastCatalogRejectedReason = ""
	state.SyncPeers[peerID] = peerState
}

func recordCatalogReject(state *stateFile, peerID, cursor, reason string, now time.Time) {
	if state == nil || peerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	if peerState.DatagramStats == nil {
		peerState.DatagramStats = &datagramStats{}
	}
	peerState.DatagramStats.LastCatalogUnix = now.Unix()
	peerState.DatagramStats.LastCatalogCursor = cursor
	peerState.DatagramStats.LastCatalogRejectedReason = reason
	state.SyncPeers[peerID] = peerState
}

func syncLimits(config *syncConfigFile) gossip.SyncLimits {
	limits := gossip.DefaultSyncLimits()
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
