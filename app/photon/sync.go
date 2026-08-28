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
	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

const defaultSyncRoundTimeout = 5 * time.Second
const syncOnceResponderQuiet = 500 * time.Millisecond
const maxRelayFanoutPerUpdate = 8

var collectSyncLocalEndpoints = gossip.CollectLocalEndpointsWithReflectors

var udpSentChunkCache = gossip.NewSentChunkCache()

type SyncRuntime struct {
	App           *Runtime
	Config        *syncConfigFile
	Transport     *gossip.Transport
	TransportDeps *SyncTransportDeps
	Observability *observability.PeerObservabilityStore
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

func syncStatus(verbose bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := readViewViaControl(rt, controlRequest{Method: "sync_view", Verbose: verbose}); err != nil {
		return err
	} else if ok {
		if response.SyncStatus == nil {
			return errors.New("daemon sync response is empty")
		}
		fmt.Fprintf(os.Stdout, "daemon: online peer_id=%s\n", response.SyncStatus.PeerID)
		return inspecttext.WriteSyncStatus(os.Stdout, *response.SyncStatus)
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
	return inspecttext.WriteSyncStatus(w, buildSyncStatusView(state.Network, state.SyncPeers, config, now, verbose))
}

func buildSyncStatusView(network *zone.NetworkState, peers map[string]syncPeerState, config *syncConfigFile, now time.Time, verbose bool) inspect.SyncStatusView {
	digests := corestate.ZoneDigests(network)
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
	discovered := gossip.ExtractPeerEndpoints(network)
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
			peerState := peers[peer.ID]
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
			peerState := peers[peerID]
			addr := "-"
			if len(entries) > 0 {
				addr = fmt.Sprintf("%s:%d", entries[0].Address, entries[0].Port)
			}
			view.Discovered = append(view.Discovered, syncVerbosePeerView(peerID, "", "", addr, peerState, now))
		}
	}
	for _, peer := range config.Bootstrap {
		peerState := peers[peer.ID]
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
		zs := network.Zones[digest.Zone]
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
	service, boltStore, err := openDaemonService(rt, defaultDaemonInterval)
	if err != nil {
		return err
	}
	defer boltStore.Close()
	config := service.Sync.Config
	logger := newAppLogger(config)
	transport, err := service.Sync.openTransport()
	if err != nil {
		return err
	}
	service.updateDiscoveredPeers()
	err = service.hostRuntime.StartGossipDatagramReceiver(ctx, transport, func(err error) {
		logger.Warn("transport", "receive_failed", map[string]any{"error": err})
	})
	if err != nil {
		return err
	}
	defer service.hostRuntime.Stop()
	service.Sync.Transport = transport
	if err := startObjectPullServer(ctx, service); err != nil {
		return err
	}
	if err := service.hostRuntime.StartGossipObjectPullWorkers(ctx, service.objectPullExecutor, 0, 0); err != nil {
		return err
	}
	stopControl, err := service.startControlServer(ctx)
	if err != nil {
		return err
	}
	defer stopControl()
	logger.Info("sync", "serve_started", map[string]any{
		"peer_id": config.PeerID,
		"addr":    transport.LocalAddr(),
	})
	for {
		select {
		case <-ctx.Done():
			return nil
		case hostEvent := <-service.hostRuntime.Events():
			if received, ok := hostEvent.(corehost.GossipPacketReceived); ok && received.Packet != nil {
				packet := received.Packet
				if err := service.processPacketEvent(packet, ctx); err != nil {
					logger.Warn("gossip", "packet_failed", addGossipErrorFields(map[string]any{
						"peer_id": packet.Message.PeerID,
						"type":    packet.Message.Type,
						"reason":  gossip.RejectReason(err),
						"error":   err,
					}, err))
				}
				continue
			}
			if event, ok := service.hostRuntime.GossipEventFor(hostEvent); ok {
				service.handleSyncEvent(ctx, event)
			}
		}
	}
}

func syncOnce(peerID string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	service, boltStore, err := openDaemonService(rt, defaultDaemonInterval)
	if err != nil {
		return err
	}
	defer boltStore.Close()
	transport, err := service.Sync.openTransport()
	if err != nil {
		return err
	}
	service.updateDiscoveredPeers()
	logger := newAppLogger(service.Sync.Config)
	ctx, cancel := context.WithTimeout(context.Background(), defaultSyncRoundTimeout)
	defer cancel()
	err = service.hostRuntime.StartGossipDatagramReceiver(ctx, transport, func(err error) {
		logger.Warn("transport", "receive_failed", map[string]any{"error": err})
	})
	if err != nil {
		return err
	}
	defer service.hostRuntime.Stop()
	service.Sync.Transport = transport
	if err := startObjectPullServer(ctx, service); err != nil {
		return err
	}
	if err := service.hostRuntime.StartGossipObjectPullWorkers(ctx, service.objectPullExecutor, 0, 0); err != nil {
		return err
	}
	if err := service.startHintedSyncSession(peerID, "sync_once"); err != nil {
		return err
	}
	var responderQuietUntil time.Time
	for {
		drained := false
		if service.hostRuntime.Gossip.Session(peerID) == nil && service.hostRuntime.PendingEventCount() == 0 && service.hostRuntime.PendingGossipObjectPullCount() == 0 {
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
		var quiet <-chan time.Time
		var quietTimer *time.Timer
		if drained && !responderQuietUntil.IsZero() {
			remaining := time.Until(responderQuietUntil)
			if remaining <= 0 {
				return nil
			}
			quietTimer = time.NewTimer(remaining)
			quiet = quietTimer.C
		}
		select {
		case <-ctx.Done():
			if quietTimer != nil {
				quietTimer.Stop()
			}
			if session := service.hostRuntime.Gossip.Session(peerID); session != nil && session.PendingCount() > 0 {
				pending := session.PendingZones()
				return &syncPendingZonesError{zones: pending}
			}
			return errors.New("sync receive timed out")
		case hostEvent := <-service.hostRuntime.Events():
			if quietTimer != nil {
				quietTimer.Stop()
			}
			if received, ok := hostEvent.(corehost.GossipPacketReceived); ok && received.Packet != nil {
				packet := received.Packet
				responderQuietUntil = time.Time{}
				if err := service.processPacketEvent(packet, ctx); err != nil {
					return err
				}
				continue
			}
			responderQuietUntil = time.Time{}
			if event, ok := service.hostRuntime.GossipEventFor(hostEvent); ok {
				service.handleSyncEvent(ctx, event)
			}
		case <-quiet:
			return nil
		}
	}
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

func recordRelaySuccessDiagnostics(store *observability.PeerObservabilityStore, peerID, sourcePeerID string, now time.Time) {
	if store == nil || peerID == "" {
		return
	}
	store.Update(peerID, now, func(diagnostics *observability.PeerDiagnostics) {
		diagnostics.LastUpdateSource = sourcePeerID
		diagnostics.LastRelaySuppression = ""
		diagnostics.LastRelaySuppressedAt = 0
	})
}

func recordRelaySuppression(store *observability.PeerObservabilityStore, peerID, reason string, now time.Time) {
	if store == nil || peerID == "" || reason == "" {
		return
	}
	store.Update(peerID, now, func(diagnostics *observability.PeerDiagnostics) {
		diagnostics.LastRelaySuppression = reason
		diagnostics.LastRelaySuppressedAt = now.Unix()
	})
}

func recordObservedSource(store *observability.PeerObservabilityStore, peerID string, source gossip.MessageType, now time.Time) {
	if store == nil || peerID == "" {
		return
	}
	store.Update(peerID, now, func(diagnostics *observability.PeerDiagnostics) {
		diagnostics.ObservedSource = string(source)
	})
}

func (sr *SyncRuntime) openTransport() (*gossip.Transport, error) {
	deps := sr.syncTransportDeps()
	listenAddr := sr.Config.ListenAddr
	if listenAddr == "" {
		listenAddr = fmt.Sprintf(":%d", gossip.DefaultPort)
	}
	datagram, err := photonlinux.ListenGossipDatagram(listenAddr)
	if err != nil {
		return nil, err
	}
	transport, err := gossip.NewTransport(sr.transportConfig(deps), datagram)
	if err != nil {
		_ = datagram.Close()
		return nil, err
	}
	sr.Transport = transport
	return transport, nil
}

func (sr *SyncRuntime) transportConfig(deps *SyncTransportDeps) gossip.Config {
	return gossip.Config{
		PeerID:          sr.Config.PeerID,
		KnownPeers:      deps.KnownPeers,
		MaxMessageBytes: sr.Config.MaxMessageBytes,
		Replay:          deps.Replay,
		Quotas:          deps.Quotas,
		Clock:           sr.now,
		Log:             deps.Log,
	}
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

func (sr *SyncRuntime) endpointProtocolIntent(verified *corestate.VerifiedState) (*corestate.PutProtocolRecordIntent, error) {
	config := sr.Config
	if verified == nil || verified.Network == nil || verified.ManagedZone == zone.RootZone || len(verified.IdentityPrivateKey) == 0 || autoJoinPendingVerified(verified) {
		return nil, nil
	}
	if config != nil && config.DisableEndpointPublish {
		return sr.clearPublishedEndpointRecordIntent(verified)
	}
	port := listenPortFromAddr(config.ListenAddr)
	advertiseAddrs, reflectors := filterEndpointDiscoveryInputs(config, port)
	endpoints, reflectorErr := collectSyncLocalEndpoints(port, advertiseAddrs, reflectors, config.ReflectorTimeout, config.FilterPrivateIPv4)
	if reflectorErr != nil && len(gossip.ResolvePublicIPReflectors(reflectors)) > 0 {
		sr.logger().Warn("endpoint", "reflector_failed", map[string]any{"error": reflectorErr})
	}
	now := sr.now()
	var previous *gossip.EndpointRecord

	zs := verified.Network.Zones[verified.ManagedZone]
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
		return nil, err
	}

	if zs != nil {
		if existing := zs.Records[gossip.EndpointRecordKeyUDP]; existing != nil {
			if bytes.Equal(existing.Value, value) || (gossip.EndpointRecordEndpointsEqual(previous, recordValue) && !endpointRefreshDue(previous, now, config.EndpointRefresh)) {
				return nil, nil
			}
		}
	}

	return &corestate.PutProtocolRecordIntent{
		Kind: corestate.ProtocolRecordGossipEndpoint, Zone: verified.ManagedZone,
		Key: gossip.EndpointRecordKeyUDP, Type: "sync.endpoint", Value: value,
	}, nil
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

func (sr *SyncRuntime) clearPublishedEndpointRecordIntent(verified *corestate.VerifiedState) (*corestate.PutProtocolRecordIntent, error) {
	config := sr.Config
	zs := verified.Network.Zones[verified.ManagedZone]
	if zs == nil {
		return nil, nil
	}
	existing := zs.Records[gossip.EndpointRecordKeyUDP]
	if existing == nil {
		return nil, nil
	}
	var current gossip.EndpointRecord
	if err := json.Unmarshal(existing.Value, &current); err == nil && len(current.Endpoints) == 0 {
		return nil, nil
	}
	now := sr.now()
	recordValue := gossip.LocalEndpointsToRecordWithPolicy(nil, nil, now, config.EndpointTTL, 0)
	value, err := json.Marshal(recordValue)
	if err != nil {
		return nil, err
	}
	return &corestate.PutProtocolRecordIntent{
		Kind: corestate.ProtocolRecordGossipEndpoint, Zone: verified.ManagedZone,
		Key: gossip.EndpointRecordKeyUDP, Type: "sync.endpoint", Value: value,
	}, nil
}

func (sr *SyncRuntime) handleObjectChunkNACKFrom(message *gossip.Message, replyAddr *net.UDPAddr) error {
	if sr == nil || sr.Transport == nil || message == nil || message.ObjectChunkNACK == nil {
		return nil
	}
	chunks := udpSentChunkCache.Repair(message.PeerID, message.ObjectChunkNACK, sr.now())
	if len(chunks) == 0 {
		recordDatagramRepairNACK(sr.Observability, message.PeerID, true, sr.now())
		return nil
	}
	for _, chunk := range chunks {
		msg := &gossip.Message{Type: gossip.MessageObjectChunk, ObjectChunk: chunk}
		var err error
		if replyAddr != nil {
			err = sr.Transport.SendTo(message.PeerID, replyAddr, msg)
		} else {
			err = sr.Transport.Send(message.PeerID, msg)
		}
		if err != nil {
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

func sendDetachedSnapshotWithDiagnosticsTo(snapshot *corestate.ZoneSnapshot, plan gossip.DatagramPlan, transport *gossip.Transport, peerID string, replyAddr *net.UDPAddr, now time.Time, logger *appLogger) (datagramSendDiagnostics, error) {
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
		msg := &gossip.Message{Type: gossip.MessageAnnounce, Announce: announce}
		var err error
		if replyAddr != nil {
			err = transport.SendTo(peerID, replyAddr, msg)
		} else {
			err = transport.Send(peerID, msg)
		}
		if err != nil {
			return diag, err
		}
	}
	chunks, err := sendDetachedZoneSnapshotChunksTo(snapshot, transport, peerID, replyAddr, now)
	diag.ChunkFallbacks = chunks
	return diag, err
}

func sendDetachedZoneSnapshotChunksTo(snapshot *corestate.ZoneSnapshot, transport *gossip.Transport, peerID string, replyAddr *net.UDPAddr, now time.Time) (int, error) {
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
		var err error
		if replyAddr != nil {
			err = transport.SendTo(peerID, replyAddr, msg)
		} else {
			err = transport.Send(peerID, msg)
		}
		if err != nil {
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
	store.Update(peerID, now, func(snapshot *observability.PeerDiagnostics) {
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
	store.Update(peerID, now, func(snapshot *observability.PeerDiagnostics) {
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
	store.Update(peerID, now, func(snapshot *observability.PeerDiagnostics) {
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
	store.Update(peerID, now, func(snapshot *observability.PeerDiagnostics) {
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
	store.Update(peerID, now, func(snapshot *observability.PeerDiagnostics) {
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
	store.Update(peerID, now, func(snapshot *observability.PeerDiagnostics) {
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
	store.Update(peerID, now, func(snapshot *observability.PeerDiagnostics) {
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
