package main

import (
	"bytes"
	"context"
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

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

const relayMinInterval = time.Second
const rejectedDigestTTL = 10 * time.Minute

var collectSyncLocalEndpoints = gossip.CollectLocalEndpointsWithReflectors

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
	fmt.Fprintf(w, "limits: max_message_bytes=%d max_sync_zones=%d max_sync_records=%d wire_version=%d\n",
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
		fmt.Fprintf(w, "zone %s root=%s records=%d history=%d delegations=%d\n",
			digest.Zone,
			hex.EncodeToString(digest.RootHash),
			len(zs.Records),
			countHistory(zs),
			len(zs.Delegations),
		)
	}
	return nil
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
	syncRuntime := newSyncRuntime(state, config, nil, rt)
	transport, err := syncRuntime.openTransport()
	if err != nil {
		return err
	}
	defer transport.Close()
	fmt.Printf("sync serving as %s on %s\n", config.PeerID, transport.LocalAddr())
	for {
		if ctx.Err() != nil {
			return nil
		}
		packet, err := receiveWithContext(ctx, transport, time.Now().Add(time.Second))
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isReceiveTimeout(err) {
				continue
			}
			fmt.Fprintf(os.Stderr, "sync receive error: %v\n", err)
			continue
		}
		if err := syncRuntime.handlePacket(packet); err != nil {
			fmt.Fprintf(os.Stderr, "sync packet error from %s: %v\n", packet.Message.PeerID, err)
			continue
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
	syncRuntime := newSyncRuntime(state, config, nil, rt)
	transport, err := syncRuntime.openTransport()
	if err != nil {
		return err
	}
	defer transport.Close()
	return syncRuntime.syncRound(context.Background(), peerID, 3*time.Second)
}

func syncRun(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = 5 * time.Second
	}
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
	syncRuntime := newSyncRuntime(state, config, nil, rt)
	transport, err := syncRuntime.openTransport()
	if err != nil {
		return err
	}
	defer transport.Close()
	fmt.Printf("sync running as %s on %s interval=%s\n", config.PeerID, transport.LocalAddr(), interval)

	nextSync := syncRuntime.now()
	nextEndpointPublish := syncRuntime.now()
	lastObservedDigests := gossip.ZoneDigests(state.Network)
	syncRuntime.updateDiscoveredPeers()
	for {
		if ctx.Err() != nil {
			return nil
		}
		now := syncRuntime.now()
		if latest, changed, err := syncRuntime.reloadStateIfChanged(lastObservedDigests); err != nil {
			fmt.Fprintf(os.Stderr, "sync reload error: %v\n", err)
		} else if changed {
			state = latest
			syncRuntime.State = latest
			lastObservedDigests = gossip.ZoneDigests(state.Network)
			nextSync = now
			syncRuntime.updateDiscoveredPeers()
		}
		if !now.Before(nextEndpointPublish) {
			if latest, err := syncRuntime.loadState(); err == nil {
				state = latest
				syncRuntime.State = latest
				if err := syncRuntime.publishEndpointRecord(); err != nil {
					fmt.Fprintf(os.Stderr, "endpoint publish error: %v\n", err)
				} else {
					lastObservedDigests = gossip.ZoneDigests(state.Network)
					nextSync = now
				}
			} else {
				fmt.Fprintf(os.Stderr, "sync reload error: %v\n", err)
			}
			interval := config.ReflectorInterval
			if interval <= 0 {
				interval = 5 * time.Minute
			}
			nextEndpointPublish = now.Add(interval)
		}
		if !now.Before(nextSync) {
			if latest, err := syncRuntime.loadState(); err == nil {
				state = latest
				syncRuntime.State = latest
				lastObservedDigests = gossip.ZoneDigests(state.Network)
			} else {
				fmt.Fprintf(os.Stderr, "sync reload error: %v\n", err)
			}
			syncRuntime.updateDiscoveredPeers()
			digestsBeforeRound := gossip.ZoneDigests(state.Network)
			for _, peerID := range outboundSyncPeers(state, config) {
				if backoffRemaining(state.SyncPeers[peerID], now) > 0 {
					continue
				}
				err := syncRuntime.syncRound(ctx, peerID, 3*time.Second)
				if err != nil {
					fmt.Fprintf(os.Stderr, "sync round error peer=%s: %v\n", peerID, err)
				}
			}
			if syncStateChanged(state, digestsBeforeRound) {
				syncRuntime.updateDiscoveredPeers()
				lastObservedDigests = gossip.ZoneDigests(state.Network)
			}
			nextSync = now.Add(interval)
		}
		packet, err := receiveWithContext(ctx, transport, syncRuntime.now().Add(250*time.Millisecond))
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isReceiveTimeout(err) || errors.Is(err, gossip.ErrUnknownPeer) || errors.Is(err, gossip.ErrAddrMismatch) || errors.Is(err, gossip.ErrMessageTooLarge) {
				continue
			}
			fmt.Fprintf(os.Stderr, "sync receive error: %v\n", err)
			continue
		}
		digestsBefore := gossip.ZoneDigests(state.Network)
		if err := syncRuntime.handlePacket(packet); err != nil {
			fmt.Fprintf(os.Stderr, "sync packet error from %s: %v\n", packet.Message.PeerID, err)
			continue
		}
		if packet.Message.Announce != nil && syncStateChanged(state, digestsBefore) {
			recordUpdateSource(state, packet.Message.PeerID)
			lastObservedDigests = gossip.ZoneDigests(state.Network)
			syncRuntime.updateDiscoveredPeers()
			if err := syncRuntime.relay(ctx, packet.Message.PeerID); err != nil {
				fmt.Fprintf(os.Stderr, "sync relay error source=%s: %v\n", packet.Message.PeerID, err)
			}
		}
	}
}

func reloadStateIfChanged(previous []gossip.ZoneDigest) (*stateFile, bool, error) {
	latest, err := loadState()
	if err != nil {
		return nil, false, err
	}
	if !sameZoneDigests(previous, gossip.ZoneDigests(latest.Network)) {
		return latest, true, nil
	}
	return latest, false, nil
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

func syncStateChanged(state *stateFile, before []gossip.ZoneDigest) bool {
	return !sameZoneDigests(before, gossip.ZoneDigests(state.Network))
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

func relaySync(ctx context.Context, state *stateFile, transport *gossip.Transport, sourcePeerID string) error {
	config, err := loadSyncConfig(state)
	if err != nil {
		return err
	}
	return newSyncRuntime(state, config, transport, nil).relay(ctx, sourcePeerID)
}

func (sr *SyncRuntime) relay(ctx context.Context, sourcePeerID string) error {
	now := sr.now()
	updatedPeerState := false
	for _, peerID := range outboundSyncPeers(sr.State, sr.Config) {
		if peerID == sourcePeerID {
			continue
		}
		allowed, reason := shouldRelayToPeer(sr.State.SyncPeers[peerID], peerID, sourcePeerID, now)
		if !allowed {
			recordRelaySuppression(sr.State, peerID, reason, now)
			updatedPeerState = true
			continue
		}
		if err := sr.syncRound(ctx, peerID, 3*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "sync relay round error peer=%s: %v\n", peerID, err)
			continue
		}
		recordRelaySuccess(sr.State, peerID, sourcePeerID, now)
		updatedPeerState = true
	}
	if updatedPeerState {
		return sr.saveState()
	}
	return nil
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
		rootHash := remoteByZone[path]
		if isRejectedDigestActive(state, peerID, path, rootHash, now) {
			continue
		}
		out = append(out, path)
	}
	return out
}

func isRejectedDigestActive(state *stateFile, peerID string, path zone.ZonePath, rootHash []byte, now time.Time) bool {
	if state == nil || peerID == "" || !path.Valid() || len(rootHash) == 0 {
		return false
	}
	peerState := state.SyncPeers[peerID]
	rejected, ok := peerState.RejectedDigests[rejectedDigestKey(path)]
	if !ok {
		return false
	}
	if rejected.RootHashHex != hex.EncodeToString(rootHash) {
		return false
	}
	return rejected.UntilUnix != 0 && now.Before(time.Unix(rejected.UntilUnix, 0))
}

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
		RootHashHex:    hex.EncodeToString(digest.RootHash),
		Reason:         reason,
		RejectedAtUnix: now.Unix(),
		UntilUnix:      now.Add(rejectedDigestTTL).Unix(),
	}
	state.SyncPeers[peerID] = peerState
}

func clearRejectedDigest(state *stateFile, peerID string, path zone.ZonePath) {
	if state == nil || peerID == "" || !path.Valid() {
		return
	}
	peerState := state.SyncPeers[peerID]
	if len(peerState.RejectedDigests) == 0 {
		return
	}
	delete(peerState.RejectedDigests, rejectedDigestKey(path))
	state.SyncPeers[peerID] = peerState
}

func rejectedDigestKey(path zone.ZonePath) string {
	return path.String()
}

func digestForZone(digests []gossip.ZoneDigest, path zone.ZonePath) gossip.ZoneDigest {
	for _, digest := range digests {
		if digest.Zone == path {
			return digest
		}
	}
	return gossip.ZoneDigest{Zone: path}
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

func recordUpdateSource(state *stateFile, sourcePeerID string) {
	if state == nil || sourcePeerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[sourcePeerID]
	peerState.LastUpdateSource = sourcePeerID
	state.SyncPeers[sourcePeerID] = peerState
}

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
	for peerID, entries := range gossip.ExtractPeerEndpoints(sr.State.Network) {
		if peerID == sr.Config.PeerID || peerID == string(sr.State.ManagedZone) {
			continue
		}
		if _, ok := deps.KnownPeers[peerID]; ok {
			continue
		}
		var addrs []*net.UDPAddr
		for _, entry := range entries {
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

func outboundSyncPeers(state *stateFile, config *syncConfigFile) []string {
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

func publishEndpointRecord(state *stateFile, config *syncConfigFile) error {
	return newSyncRuntime(state, config, nil, nil).publishEndpointRecord()
}

func (sr *SyncRuntime) publishEndpointRecord() error {
	state := sr.State
	config := sr.Config
	port := listenPortFromAddr(config.ListenAddr)
	endpoints, reflectorErr := collectSyncLocalEndpoints(port, config.AdvertiseAddrs, config.Reflectors, config.ReflectorTimeout, config.FilterPrivateIPv4)
	if reflectorErr != nil && len(gossip.ResolvePublicIPReflectors(config.Reflectors)) > 0 {
		fmt.Fprintf(os.Stderr, "reflector discovery warning: %v\n", reflectorErr)
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
		return err
	}

	if zs != nil {
		if existing := zs.Records[gossip.EndpointRecordKeyUDP]; existing != nil {
			if bytes.Equal(existing.Value, value) {
				return nil
			}
		}
	}

	record, err := buildSignedRecordAt(state, state.ManagedZone, gossip.EndpointRecordKeyUDP, value, "sync.endpoint", now)
	if err != nil {
		return err
	}
	if err := state.Network.Put(record); err != nil {
		return err
	}
	return sr.saveState()
}

func addVerifiedZonePeers(state *stateFile, transport *gossip.Transport, config *syncConfigFile) {
	newSyncRuntime(state, config, transport, nil).addVerifiedZonePeers()
}

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
}

func updateDiscoveredPeers(state *stateFile, transport *gossip.Transport, config *syncConfigFile) {
	newSyncRuntime(state, config, transport, nil).updateDiscoveredPeers()
}

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
	for peerID, entries := range discovered {
		if peerID == config.PeerID || peerID == string(state.ManagedZone) {
			continue
		}
		if len(entries) == 0 {
			continue
		}
		var addrs []*net.UDPAddr
		for _, entry := range entries {
			addr, err := entry.UDPAddr()
			if err != nil {
				continue
			}
			addrs = appendUDPAddrOnce(addrs, addr)
		}
		addrs = appendRecentSuccessfulDiscoveredAddr(addrs, state.SyncPeers[peerID], config.EndpointGrace, now)
		if bootstrapAddr := bootstrapPeers[peerID]; bootstrapAddr != nil {
			addrs = appendUDPAddrOnce(addrs, bootstrapAddr)
		}
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
			fmt.Fprintf(os.Stderr, "update discovered peers save error: %v\n", err)
		}
	}
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

func syncRoundWithTransport(ctx context.Context, state *stateFile, transport *gossip.Transport, peerID string, timeout time.Duration) (err error) {
	config, configErr := loadSyncConfig(state)
	if configErr != nil {
		return configErr
	}
	return newSyncRuntime(state, config, transport, nil).syncRound(ctx, peerID, timeout)
}

func (sr *SyncRuntime) syncRound(ctx context.Context, peerID string, timeout time.Duration) (err error) {
	defer func() {
		recordPeerSyncAt(sr.State, peerID, err, sr.now())
		if saveErr := sr.saveState(); err == nil && saveErr != nil {
			err = saveErr
		}
	}()
	if err := sr.Transport.Send(peerID, &gossip.Message{
		Type: gossip.MessagePing,
		Ping: &gossip.Ping{Zones: gossip.ZoneDigests(sr.State.Network)},
	}); err != nil {
		return err
	}

	deadline := sr.now().Add(timeout)
	for sr.now().Before(deadline) {
		packet, receiveErr := receiveWithContext(ctx, sr.Transport, deadline)
		if receiveErr != nil && isReceiveTimeout(receiveErr) && sr.now().Before(deadline) {
			continue
		}
		if receiveErr != nil {
			err = receiveErr
			return err
		}
		if packet.Message.PeerID != peerID {
			if handleErr := sr.handlePacket(packet); handleErr != nil {
				fmt.Fprintf(os.Stderr, "sync packet error from %s: %v\n", packet.Message.PeerID, handleErr)
			}
			continue
		}
		var waitingForAnnounce bool
		if packet.Message.Pong != nil {
			waitingForAnnounce = len(gossip.FetchList(sr.State.Network, packet.Message.Pong.Zones)) > 0
		}
		if err = sr.handlePacket(packet); err != nil {
			return err
		}
		if packet.Message.Pong != nil && !waitingForAnnounce {
			return nil
		}
		if packet.Message.Announce != nil {
			return nil
		}
	}
	err = errors.New("sync once timed out")
	return err
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

func handleSyncPacket(state *stateFile, transport *gossip.Transport, packet *gossip.Packet) (err error) {
	config, configErr := loadSyncConfig(state)
	if configErr != nil {
		return configErr
	}
	return newSyncRuntime(state, config, transport, nil).handlePacket(packet)
}

func (sr *SyncRuntime) handlePacket(packet *gossip.Packet) (err error) {
	state := sr.State
	transport := sr.Transport
	config := sr.Config
	configureValidation(state.Network)
	message := packet.Message
	defer func() {
		recordPeerSyncAt(state, message.PeerID, err, sr.now())
		if err != nil && debugLogEnabled(config) {
			reason := gossip.RejectReason(err)
			if reason == "invalid_message" {
				reason = "verify_failed"
			}
			event := gossip.Event{
				Direction: "handle",
				PeerID:    message.PeerID,
				Type:      message.Type,
				Reason:    reason,
				Error:     err.Error(),
			}
			if config != nil {
				if logger := syncDebugLogger(config); logger != nil {
					logger(event)
				}
			}
		}
		if saveErr := sr.saveState(); err == nil && saveErr != nil {
			err = saveErr
		}
	}()
	switch message.Type {
	case gossip.MessagePing:
		fetch := fetchListForPeer(state, message.PeerID, message.Ping.Zones, sr.now())
		return transport.Send(message.PeerID, &gossip.Message{
			Type: gossip.MessagePong,
			Pong: &gossip.Pong{Zones: gossip.ZoneDigests(state.Network), FetchZones: fetch},
		})
	case gossip.MessagePong:
		if len(message.Pong.FetchZones) == 0 {
			for _, path := range fetchListForPeer(state, message.PeerID, message.Pong.Zones, sr.now()) {
				if err := transport.Send(message.PeerID, &gossip.Message{
					Type:      gossip.MessageFetchZone,
					FetchZone: &gossip.FetchZone{Zone: path},
				}); err != nil {
					return err
				}
			}
			return nil
		}
		if err := sendSnapshots(state.Network, transport, message.PeerID, message.Pong.FetchZones); err != nil {
			return err
		}
		for _, path := range fetchListForPeer(state, message.PeerID, message.Pong.Zones, sr.now()) {
			if err := transport.Send(message.PeerID, &gossip.Message{
				Type:      gossip.MessageFetchZone,
				FetchZone: &gossip.FetchZone{Zone: path},
			}); err != nil {
				return err
			}
		}
		return nil
	case gossip.MessageFetchZone:
		return sendSnapshots(state.Network, transport, message.PeerID, []zone.ZonePath{message.FetchZone.Zone})
	case gossip.MessageFetchRecord:
		return sendRecord(state.Network, transport, message.PeerID, message.FetchRecord)
	case gossip.MessageAnnounce:
		return sr.handleAnnounce(message, syncLimits(config))
	default:
		return nil
	}
}

func handleAnnounce(state *stateFile, transport *gossip.Transport, message *gossip.Message, limits gossip.SyncLimits) error {
	config, err := loadSyncConfig(state)
	if err != nil {
		return err
	}
	return newSyncRuntime(state, config, transport, nil).handleAnnounce(message, limits)
}

func (sr *SyncRuntime) handleAnnounce(message *gossip.Message, limits gossip.SyncLimits) error {
	state := sr.State
	transport := sr.Transport
	var changed bool
	if limits.MaxZones > 0 && len(message.Announce.Snapshots) > limits.MaxZones {
		return gossip.ErrZoneSnapshotTooLarge
	}
	if limits.MaxRecords > 0 && len(message.Announce.Records) > limits.MaxRecords {
		return gossip.ErrZoneSnapshotTooLarge
	}
	for _, snapshot := range message.Announce.Snapshots {
		result, err := gossip.ApplySnapshot(state.Network, &snapshot, sr.now(), limits)
		if err != nil {
			recordRejectedDigest(state, message.PeerID, digestForZone(message.Announce.Zones, snapshot.Zone), gossip.RejectReason(err), sr.now())
			return err
		}
		clearRejectedDigest(state, message.PeerID, snapshot.Zone)
		changed = true
		fmt.Printf("applied zone %s records=%d delegations=%d\n", result.Zone, result.Records, result.Delegation)
	}
	for _, record := range message.Announce.Records {
		err := gossip.ApplyRecordSnapshot(state.Network, &record, sr.now())
		if err != nil {
			return err
		}
		changed = true
	}
	if changed {
		if err := sr.saveState(); err != nil {
			return err
		}
	}
	for _, path := range fetchListForPeer(state, message.PeerID, message.Announce.Zones, sr.now()) {
		if err := transport.Send(message.PeerID, &gossip.Message{
			Type:      gossip.MessageFetchZone,
			FetchZone: &gossip.FetchZone{Zone: path},
		}); err != nil {
			return err
		}
	}
	return nil
}

func sendSnapshots(ns *zone.NetworkState, transport *gossip.Transport, peerID string, zones []zone.ZonePath) error {
	sort.Slice(zones, func(i, j int) bool { return zones[i] < zones[j] })
	var snapshots []gossip.ZoneSnapshot
	for _, path := range zones {
		snapshot, err := gossip.Snapshot(ns, path)
		if err != nil {
			continue
		}
		snapshots = append(snapshots, *snapshot)
	}
	if len(snapshots) == 0 {
		return nil
	}
	return transport.Send(peerID, &gossip.Message{
		Type:     gossip.MessageAnnounce,
		Announce: &gossip.Announce{Zones: gossip.ZoneDigests(ns), Snapshots: snapshots},
	})
}

func sendRecord(ns *zone.NetworkState, transport *gossip.Transport, peerID string, fetch *gossip.FetchRecord) error {
	record, err := gossip.RecordSnapshotFor(ns, fetch)
	if err != nil {
		return nil
	}
	return transport.Send(peerID, &gossip.Message{
		Type:     gossip.MessageAnnounce,
		Announce: &gossip.Announce{Records: []gossip.RecordSnapshot{*record}},
	})
}

func loadSyncConfig(state *stateFile) (*syncConfigFile, error) {
	return configuredSyncConfig(state)
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
