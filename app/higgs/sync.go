package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
)

func syncStatus() error {
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
		fmt.Printf("peer %s addr=%s last_sync=%s known_zones=%d pending=%d last_error=%s\n",
			peer.ID,
			peer.Addr,
			lastSync,
			len(digests),
			pending,
			lastError,
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

func syncServe() error {
	state, err := loadState()
	if err != nil {
		return err
	}
	config, err := loadSyncConfig(state)
	if err != nil {
		return err
	}
	transport, err := gossip.Listen(gossip.Config{
		PeerID:          config.PeerID,
		ListenAddr:      config.ListenAddr,
		KnownPeers:      configuredKnownPeers(config),
		MaxMessageBytes: config.MaxMessageBytes,
		Replay:          gossip.NewReplayWindow(0),
		Quotas:          gossip.NewPeerQuotas(gossip.QuotaConfig{}),
	})
	if err != nil {
		return err
	}
	defer transport.Close()
	fmt.Printf("sync serving as %s on %s\n", config.PeerID, transport.LocalAddr())
	for {
		packet, err := transport.Receive()
		if err != nil {
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
	transport, err := gossip.Listen(gossip.Config{
		PeerID:          config.PeerID,
		ListenAddr:      config.ListenAddr,
		KnownPeers:      configuredKnownPeers(config),
		MaxMessageBytes: config.MaxMessageBytes,
		Replay:          gossip.NewReplayWindow(0),
		Quotas:          gossip.NewPeerQuotas(gossip.QuotaConfig{}),
	})
	if err != nil {
		return err
	}
	defer transport.Close()
	if err := transport.Send(peerID, &gossip.Message{
		Type: gossip.MessagePing,
		Ping: &gossip.Ping{Zones: gossip.ZoneDigests(state.Network)},
	}); err != nil {
		return err
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = transport.LocalAddr()
		packet, err := receiveWithDeadline(transport, deadline)
		if err != nil {
			return err
		}
		if packet.Message.PeerID != peerID {
			continue
		}
		var waitingForAnnounce bool
		if packet.Message.Pong != nil {
			waitingForAnnounce = len(gossip.FetchList(state.Network, packet.Message.Pong.Zones)) > 0
		}
		if err := handleSyncPacket(state, transport, packet); err != nil {
			return err
		}
		if packet.Message.Pong != nil && !waitingForAnnounce {
			return nil
		}
		if packet.Message.Announce != nil {
			return nil
		}
	}
	return errors.New("sync once timed out")
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
		if errors.Is(err, gossip.ErrUnknownPeer) || errors.Is(err, gossip.ErrMessageTooLarge) {
			continue
		}
		return nil, err
	}
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
