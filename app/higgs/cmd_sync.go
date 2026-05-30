package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/urfave/cli/v3"
)

func cmdSync() *cli.Command {
	return &cli.Command{
		Name:  "sync",
		Usage: "Gossip sync commands",
		Commands: []*cli.Command{
			{
				Name:        "status",
				Usage:       "Show sync and peer status",
				Description: "Display current sync configuration, known peers, and zone digests.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return syncStatus()
				},
			},
			{
				Name:        "serve",
				Usage:       "Start the gossip sync server",
				Description: "Listen for incoming sync messages and respond to pings/pongs.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return syncServe()
				},
			},
			{
				Name:      "once",
				Usage:     "Run a single sync round with a peer",
				UsageText: "higgs sync once <peer-id>",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: higgs sync once <peer-id>", 1)
					}
					return syncOnce(cmd.Args().First())
				},
			},
		},
	}
}

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
	}
	return nil
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
		PeerID:     config.PeerID,
		ListenAddr: config.ListenAddr,
		KnownPeers: configuredKnownPeers(config),
		Replay:     gossip.NewReplayWindow(0),
		Quotas:     gossip.NewPeerQuotas(gossip.QuotaConfig{}),
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
		PeerID:     config.PeerID,
		ListenAddr: config.ListenAddr,
		KnownPeers: configuredKnownPeers(config),
		Replay:     gossip.NewReplayWindow(0),
		Quotas:     gossip.NewPeerQuotas(gossip.QuotaConfig{}),
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
		return handleAnnounce(state, transport, message)
	default:
		return nil
	}
}

func handleAnnounce(state *stateFile, transport *gossip.Transport, message *gossip.Message) error {
	var changed bool
	for _, snapshot := range message.Announce.Snapshots {
		result, err := gossip.ApplySnapshot(state.Network, &snapshot, time.Now(), gossip.DefaultSyncLimits())
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
	for path, zs := range ns.Zones {
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
				if err := transport.Send(peerID, &gossip.Message{
					Type: gossip.MessageFetchRecord,
					FetchRecord: &gossip.FetchRecord{
						Zone:    path,
						Key:     key,
						Version: record.Version - 1,
					},
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func loadSyncConfig(state *stateFile) (*syncConfigFile, error) {
	return configuredSyncConfig(state)
}
