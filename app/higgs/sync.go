package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
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

func syncStatus(verbose bool) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	config, err := loadSyncConfig(state)
	if err != nil {
		return err
	}
	fmt.Printf("peer_id: %s\n", config.PeerID)
	fmt.Printf("listen_addr: %s\n", config.ListenAddr)
	digests := gossip.ZoneDigests(state.Network)
	fmt.Printf("known_peers: %d\n", len(config.Bootstrap))
	fmt.Printf("known_zones: %d\n", len(digests))
	fmt.Printf("local_root: %s\n", hex.EncodeToString(globalRootHash(digests)))
	fmt.Printf("limits: max_message_bytes=%d max_sync_zones=%d max_sync_records=%d wire_version=%d\n",
		config.MaxMessageBytes,
		config.MaxSyncZones,
		config.MaxSyncRecords,
		gossip.WireVersion,
	)
	discovered := gossip.ExtractPeerEndpoints(state.Network)
	if verbose {
		known := configuredKnownPeers(config)
		fmt.Printf("allowlist_source: bootstrap+discovery\n")
		fmt.Printf("bootstrap_peers: %d\n", len(config.Bootstrap))
		var discoveredCount int
		for peerID := range discovered {
			if !isBootstrapPeer(config, peerID) {
				discoveredCount++
			}
		}
		fmt.Printf("discovered_peers: %d\n", discoveredCount)
		for _, peer := range config.Bootstrap {
			resolved := "-"
			if addr := known[peer.ID]; addr != nil {
				resolved = addr.String()
			}
			peerState := state.SyncPeers[peer.ID]
			fmt.Printf("bootstrap peer=%s configured_addr=%s resolved_addr=%s status=%s last_success=%s last_error=%s next_retry=%s\n",
				peer.ID,
				peer.Addr,
				resolved,
				peerStatus(peerState, time.Now()),
				formatLastSuccess(peerState),
				dash(peerState.LastError),
				formatNextRetry(peerState, time.Now()),
			)
			fmt.Printf("  update_source=%s last_relay=%s relay_suppression=%s\n",
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
			fmt.Printf("discovered peer=%s addr=%s status=%s last_success=%s\n",
				peerID,
				addr,
				peerStatus(peerState, time.Now()),
				formatLastSuccess(peerState),
			)
		}
	}
	now := time.Now()
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
		fmt.Printf("peer %s addr=%s status=%s last_sync=%s known_zones=%d last_error=%s next_retry=%s\n",
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
		fmt.Printf("zone %s root=%s records=%d history=%d delegations=%d\n",
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
	state, err := loadState()
	if err != nil {
		return err
	}
	config, err := loadSyncConfig(state)
	if err != nil {
		return err
	}
	transport, err := openSyncTransport(config, state)
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
		if err := handleSyncPacket(state, transport, packet); err != nil {
			fmt.Fprintf(os.Stderr, "sync packet error from %s: %v\n", packet.Message.PeerID, err)
			continue
		}
	}
}

func syncOnce(peerID string) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	config, err := loadSyncConfig(state)
	if err != nil {
		return err
	}
	transport, err := openSyncTransport(config, state)
	if err != nil {
		return err
	}
	defer transport.Close()
	return syncRoundWithTransport(context.Background(), state, transport, peerID, 3*time.Second)
}

func syncRun(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	state, err := loadState()
	if err != nil {
		return err
	}
	config, err := loadSyncConfig(state)
	if err != nil {
		return err
	}
	transport, err := openSyncTransport(config, state)
	if err != nil {
		return err
	}
	defer transport.Close()
	fmt.Printf("sync running as %s on %s interval=%s\n", config.PeerID, transport.LocalAddr(), interval)

	nextSync := time.Now()
	nextEndpointPublish := time.Now()
	lastObservedDigests := gossip.ZoneDigests(state.Network)
	updateDiscoveredPeers(state, transport, config)
	for {
		if ctx.Err() != nil {
			return nil
		}
		now := time.Now()
		if latest, changed, err := reloadStateIfChanged(lastObservedDigests); err != nil {
			fmt.Fprintf(os.Stderr, "sync reload error: %v\n", err)
		} else if changed {
			state = latest
			lastObservedDigests = gossip.ZoneDigests(state.Network)
			nextSync = now
			updateDiscoveredPeers(state, transport, config)
		}
		if !now.Before(nextEndpointPublish) {
			if latest, err := loadState(); err == nil {
				state = latest
				if err := publishEndpointRecord(state, config); err != nil {
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
			if latest, err := loadState(); err == nil {
				state = latest
				lastObservedDigests = gossip.ZoneDigests(state.Network)
			} else {
				fmt.Fprintf(os.Stderr, "sync reload error: %v\n", err)
			}
			updateDiscoveredPeers(state, transport, config)
			digestsBeforeRound := gossip.ZoneDigests(state.Network)
			for _, peerID := range outboundSyncPeers(state, config) {
				if backoffRemaining(state.SyncPeers[peerID], now) > 0 {
					continue
				}
				err := syncRoundWithTransport(ctx, state, transport, peerID, 3*time.Second)
				if err != nil {
					fmt.Fprintf(os.Stderr, "sync round error peer=%s: %v\n", peerID, err)
				}
			}
			if syncStateChanged(state, digestsBeforeRound) {
				updateDiscoveredPeers(state, transport, config)
				lastObservedDigests = gossip.ZoneDigests(state.Network)
			}
			nextSync = now.Add(interval)
		}
		packet, err := receiveWithContext(ctx, transport, time.Now().Add(250*time.Millisecond))
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
		if err := handleSyncPacket(state, transport, packet); err != nil {
			fmt.Fprintf(os.Stderr, "sync packet error from %s: %v\n", packet.Message.PeerID, err)
			continue
		}
		if packet.Message.Announce != nil && syncStateChanged(state, digestsBefore) {
			recordUpdateSource(state, packet.Message.PeerID)
			lastObservedDigests = gossip.ZoneDigests(state.Network)
			updateDiscoveredPeers(state, transport, config)
			if err := relaySync(ctx, state, transport, packet.Message.PeerID); err != nil {
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
	now := time.Now()
	updatedPeerState := false
	for _, peerID := range outboundSyncPeers(state, config) {
		if peerID == sourcePeerID {
			continue
		}
		allowed, reason := shouldRelayToPeer(state.SyncPeers[peerID], peerID, sourcePeerID, now)
		if !allowed {
			recordRelaySuppression(state, peerID, reason, now)
			updatedPeerState = true
			continue
		}
		if err := syncRoundWithTransport(ctx, state, transport, peerID, 3*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "sync relay round error peer=%s: %v\n", peerID, err)
			continue
		}
		recordRelaySuccess(state, peerID, sourcePeerID, now)
		updatedPeerState = true
	}
	if updatedPeerState {
		return saveState(state)
	}
	return nil
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
	bootstrapPeers := configuredKnownPeers(config)
	transport, err := gossip.Listen(gossip.Config{
		PeerID:          config.PeerID,
		ListenAddr:      config.ListenAddr,
		KnownPeers:      bootstrapPeers,
		MaxMessageBytes: config.MaxMessageBytes,
		Replay:          gossip.NewReplayWindow(0),
		Quotas:          gossip.NewPeerQuotas(gossip.QuotaConfig{}),
		Log:             syncDebugLogger(config),
	})
	if err != nil {
		return nil, err
	}
	if state != nil {
		addVerifiedZonePeers(state, transport, config)
		for peerID, entries := range gossip.ExtractPeerEndpoints(state.Network) {
			if peerID == config.PeerID || peerID == string(state.ManagedZone) {
				continue
			}
			if _, ok := bootstrapPeers[peerID]; ok {
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
				transport.SetPeerAddrs(peerID, addrs)
			}
		}
	}
	return transport, nil
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
	port := listenPortFromAddr(config.ListenAddr)
	endpoints := gossip.CollectLocalEndpoints(port, config.AdvertiseAddrs)
	value := gossip.EndpointRecordBytes(endpoints, time.Now())

	zs := state.Network.Zones[state.ManagedZone]
	if zs != nil {
		if existing := zs.Records[gossip.EndpointRecordKeyUDP]; existing != nil {
			if bytes.Equal(existing.Value, value) {
				return nil
			}
		}
	}

	record, err := buildSignedRecord(state, state.ManagedZone, gossip.EndpointRecordKeyUDP, value, "sync.endpoint")
	if err != nil {
		return err
	}
	if err := state.Network.Put(record); err != nil {
		return err
	}
	return saveState(state)
}

func addVerifiedZonePeers(state *stateFile, transport *gossip.Transport, config *syncConfigFile) {
	if state == nil || state.Network == nil {
		return
	}
	configureValidation(state.Network)
	now := time.Now()
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
	addVerifiedZonePeers(state, transport, config)
	discovered := gossip.ExtractPeerEndpoints(state.Network)
	now := time.Now()
	updated := false
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
			addrs = append(addrs, addr)
		}
		if len(addrs) == 0 {
			continue
		}
		transport.SetPeerAddrs(peerID, addrs)
		normalizeSyncPeers(state)
		ps := state.SyncPeers[peerID]
		ps.DiscoveredAddr = addrs[0].String()
		ps.DiscoveredAtUnix = now.Unix()
		state.SyncPeers[peerID] = ps
		updated = true
	}
	if updated {
		if err := saveState(state); err != nil {
			fmt.Fprintf(os.Stderr, "update discovered peers save error: %v\n", err)
		}
	}
}

func syncRoundWithTransport(ctx context.Context, state *stateFile, transport *gossip.Transport, peerID string, timeout time.Duration) (err error) {
	defer func() {
		recordPeerSync(state, peerID, err)
		if saveErr := saveState(state); err == nil && saveErr != nil {
			err = saveErr
		}
	}()
	if err := transport.Send(peerID, &gossip.Message{
		Type: gossip.MessagePing,
		Ping: &gossip.Ping{Zones: gossip.ZoneDigests(state.Network)},
	}); err != nil {
		return err
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		packet, receiveErr := receiveWithContext(ctx, transport, deadline)
		if receiveErr != nil && isReceiveTimeout(receiveErr) && time.Now().Before(deadline) {
			continue
		}
		if receiveErr != nil {
			err = receiveErr
			return err
		}
		if packet.Message.PeerID != peerID {
			if handleErr := handleSyncPacket(state, transport, packet); handleErr != nil {
				fmt.Fprintf(os.Stderr, "sync packet error from %s: %v\n", packet.Message.PeerID, handleErr)
			}
			continue
		}
		var waitingForAnnounce bool
		if packet.Message.Pong != nil {
			waitingForAnnounce = len(gossip.FetchList(state.Network, packet.Message.Pong.Zones)) > 0
		}
		if err = handleSyncPacket(state, transport, packet); err != nil {
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
	configureValidation(state.Network)
	config, configErr := loadSyncConfig(state)
	if configErr != nil {
		return configErr
	}
	message := packet.Message
	defer func() {
		recordPeerSync(state, message.PeerID, err)
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
		if saveErr := saveState(state); err == nil && saveErr != nil {
			err = saveErr
		}
	}()
	switch message.Type {
	case gossip.MessagePing:
		fetch := gossip.FetchList(state.Network, message.Ping.Zones)
		return transport.Send(message.PeerID, &gossip.Message{
			Type: gossip.MessagePong,
			Pong: &gossip.Pong{Zones: gossip.ZoneDigests(state.Network), FetchZones: fetch},
		})
	case gossip.MessagePong:
		if len(message.Pong.FetchZones) == 0 {
			for _, path := range gossip.FetchList(state.Network, message.Pong.Zones) {
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
		for _, path := range gossip.FetchList(state.Network, message.Pong.Zones) {
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
		return handleAnnounce(state, transport, message, syncLimits(config))
	default:
		return nil
	}
}

func handleAnnounce(state *stateFile, transport *gossip.Transport, message *gossip.Message, limits gossip.SyncLimits) error {
	var changed bool
	if limits.MaxZones > 0 && len(message.Announce.Snapshots) > limits.MaxZones {
		return gossip.ErrZoneSnapshotTooLarge
	}
	if limits.MaxRecords > 0 && len(message.Announce.Records) > limits.MaxRecords {
		return gossip.ErrZoneSnapshotTooLarge
	}
	for _, snapshot := range message.Announce.Snapshots {
		result, err := gossip.ApplySnapshot(state.Network, &snapshot, time.Now(), limits)
		if err != nil {
			return err
		}
		changed = true
		fmt.Printf("applied zone %s records=%d delegations=%d\n", result.Zone, result.Records, result.Delegation)
	}
	for _, record := range message.Announce.Records {
		err := gossip.ApplyRecordSnapshot(state.Network, &record, time.Now())
		if err != nil {
			return err
		}
		changed = true
	}
	if changed {
		if err := saveState(state); err != nil {
			return err
		}
	}
	for _, path := range gossip.FetchList(state.Network, message.Announce.Zones) {
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
