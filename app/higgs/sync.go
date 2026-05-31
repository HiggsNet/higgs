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
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
)

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
	pending := totalPending(state.Network)
	fmt.Printf("known_peers: %d\n", len(config.Bootstrap))
	fmt.Printf("known_zones: %d\n", len(digests))
	fmt.Printf("pending_records: %d\n", pending)
	fmt.Printf("local_root: %s\n", hex.EncodeToString(globalRootHash(digests)))
	fmt.Printf("limits: max_message_bytes=%d max_sync_zones=%d max_sync_records=%d wire_version=%d\n",
		config.MaxMessageBytes,
		config.MaxSyncZones,
		config.MaxSyncRecords,
		gossip.WireVersion,
	)
	if verbose {
		known := configuredKnownPeers(config)
		fmt.Printf("allowlist_source: bootstrap\n")
		fmt.Printf("bootstrap_peers: %d\n", len(config.Bootstrap))
		fmt.Printf("discovered_peers: 0\n")
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
		fmt.Printf("peer %s addr=%s status=%s last_sync=%s known_zones=%d pending=%d last_error=%s next_retry=%s\n",
			peer.ID,
			peer.Addr,
			peerStatus(peerState, now),
			lastSync,
			len(digests),
			pending,
			lastError,
			formatNextRetry(peerState, now),
		)
	}
	for _, digest := range digests {
		zs := state.Network.Zones[digest.Zone]
		fmt.Printf("zone %s root=%s records=%d pending=%d delegations=%d\n",
			digest.Zone,
			hex.EncodeToString(digest.RootHash),
			len(zs.Records),
			countPending(zs),
			len(zs.Delegations),
		)
		printPendingRecords(zs)
	}
	return nil
}

func printPendingRecords(zs *zone.ZoneState) {
	if zs == nil || len(zs.PendingRecords) == 0 {
		return
	}
	keys := make([]string, 0, len(zs.PendingRecords))
	for key := range zs.PendingRecords {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, record := range zs.PendingRecords[key] {
			if record == nil {
				continue
			}
			fmt.Printf("  pending key=%s version=%d missing_prev=%d\n", key, record.Version, missingPredecessorVersion(record))
		}
	}
}

func missingPredecessorVersion(record *zone.Record) uint64 {
	if record == nil || record.Version <= 1 {
		return 0
	}
	return record.Version - 1
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
	transport, err := openSyncTransport(config)
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
	transport, err := openSyncTransport(config)
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
	transport, err := openSyncTransport(config)
	if err != nil {
		return err
	}
	defer transport.Close()
	fmt.Printf("sync running as %s on %s interval=%s\n", config.PeerID, transport.LocalAddr(), interval)

	nextSync := time.Now()
	for {
		if ctx.Err() != nil {
			return nil
		}
		now := time.Now()
		if !now.Before(nextSync) {
			if latest, err := loadState(); err == nil {
				state = latest
			} else {
				fmt.Fprintf(os.Stderr, "sync reload error: %v\n", err)
			}
			for _, peer := range config.Bootstrap {
				if peer.ID == "" {
					continue
				}
				if backoffRemaining(state.SyncPeers[peer.ID], now) > 0 {
					continue
				}
				err := syncRoundWithTransport(ctx, state, transport, peer.ID, 3*time.Second)
				if err != nil {
					fmt.Fprintf(os.Stderr, "sync round error peer=%s: %v\n", peer.ID, err)
				}
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
			if err := relaySync(ctx, state, transport, packet.Message.PeerID); err != nil {
				fmt.Fprintf(os.Stderr, "sync relay error source=%s: %v\n", packet.Message.PeerID, err)
			}
		}
	}
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
	for _, peer := range config.Bootstrap {
		if peer.ID == "" || peer.ID == sourcePeerID {
			continue
		}
		if backoffRemaining(state.SyncPeers[peer.ID], now) > 0 {
			continue
		}
		if err := syncRoundWithTransport(ctx, state, transport, peer.ID, 3*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "sync relay round error peer=%s: %v\n", peer.ID, err)
		}
	}
	return nil
}

func openSyncTransport(config *syncConfigFile) (*gossip.Transport, error) {
	return gossip.Listen(gossip.Config{
		PeerID:          config.PeerID,
		ListenAddr:      config.ListenAddr,
		KnownPeers:      configuredKnownPeers(config),
		MaxMessageBytes: config.MaxMessageBytes,
		Replay:          gossip.NewReplayWindow(0),
		Quotas:          gossip.NewPeerQuotas(gossip.QuotaConfig{}),
		Log:             syncDebugLogger(config),
	})
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
		fmt.Printf("applied zone %s records=%d pending=%d delegations=%d\n", result.Zone, result.Records, result.Pending, result.Delegation)
	}
	for _, record := range message.Announce.Records {
		err := gossip.ApplyRecordSnapshot(state.Network, &record, time.Now())
		if err != nil && !errors.Is(err, zone.ErrPendingRecord) {
			return err
		}
		changed = true
	}
	if changed {
		if err := saveState(state); err != nil {
			return err
		}
	}
	if err := fetchPendingPredecessors(state.Network, transport, message.PeerID); err != nil {
		return err
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

func fetchPendingPredecessors(ns *zone.NetworkState, transport *gossip.Transport, peerID string) error {
	for _, fetch := range pendingPredecessorFetches(ns) {
		fetch := fetch
		if err := transport.Send(peerID, &gossip.Message{
			Type:        gossip.MessageFetchRecord,
			FetchRecord: &fetch,
		}); err != nil {
			return err
		}
	}
	return nil
}

func pendingPredecessorFetches(ns *zone.NetworkState) []gossip.FetchRecord {
	if ns == nil {
		return nil
	}
	paths := make([]zone.ZonePath, 0, len(ns.Zones))
	for path := range ns.Zones {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	var out []gossip.FetchRecord
	for _, path := range paths {
		zs := ns.Zones[path]
		if zs == nil {
			continue
		}
		keys := make([]string, 0, len(zs.PendingRecords))
		for key := range zs.PendingRecords {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			for _, record := range zs.PendingRecords[key] {
				if record == nil || record.Version <= 1 {
					continue
				}
				out = append(out, gossip.FetchRecord{
					Zone:    path,
					Key:     key,
					Version: record.Version - 1,
				})
			}
		}
	}
	return out
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
