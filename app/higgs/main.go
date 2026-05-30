package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	bolt "go.etcd.io/bbolt"
)

const defaultStatePath = ".higgs.db"
const cliMetaKey = "cli_state"

type stateFile struct {
	ManagedZone    zone.ZonePath      `json:"managed_zone"`
	RootPrivateKey ed25519.PrivateKey `json:"root_private_key"`
	ZonePrivateKey ed25519.PrivateKey `json:"zone_private_key"`
	Network        *zone.NetworkState `json:"network"`
	SyncPeers      map[string]syncPeerState
}

type stateMeta struct {
	ManagedZone    zone.ZonePath            `json:"managed_zone"`
	RootPrivateKey ed25519.PrivateKey       `json:"root_private_key"`
	ZonePrivateKey ed25519.PrivateKey       `json:"zone_private_key"`
	SyncPeers      map[string]syncPeerState `json:"sync_peers,omitempty"`
}

type syncPeerState struct {
	LastSyncUnix int64  `json:"last_sync_unix,omitempty"`
	LastError    string `json:"last_error,omitempty"`
}

type syncConfigFile struct {
	PeerID     string           `json:"peer_id"`
	ListenAddr string           `json:"listen_addr"`
	Bootstrap  []syncConfigPeer `json:"bootstrap"`
}

type syncConfigPeer struct {
	ID   string `json:"id"`
	Addr string `json:"addr"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}

	switch args[0] {
	case "init":
		managedZone := zone.ZonePath("local.")
		if len(args) > 1 {
			managedZone = zone.ZonePath(args[1])
		}
		return initState(managedZone)
	case "root":
		return runRoot(args[1:])
	case "keygen":
		if len(args) != 2 {
			return usage()
		}
		return keygen(args[1])
	case "join":
		return runJoin(args[1:])
	case "delegate":
		return runDelegate(args[1:])
	case "zone":
		if len(args) != 3 || args[1] != "show" {
			return usage()
		}
		return showZone(zone.ZonePath(args[2]))
	case "record":
		if len(args) < 5 || args[1] != "put" {
			return usage()
		}
		recordType := "policy.string"
		if len(args) > 5 {
			recordType = args[5]
		}
		return putRecord(zone.ZonePath(args[2]), args[3], []byte(args[4]), recordType)
	case "verify":
		if len(args) == 2 {
			return verifyChain(zone.ZonePath(args[1]))
		}
		if len(args) == 3 && args[1] == "chain" {
			return verifyChain(zone.ZonePath(args[2]))
		}
		return usage()
	case "sync":
		return runSync(args[1:])
	case "db":
		return runDB(args[1:])
	default:
		return usage()
	}
}

func usage() error {
	return errors.New("usage: higgs root init | higgs root pubkey | higgs keygen <key.json> | higgs join request <zone> <key.json> <request.json> | higgs delegate issue <request.json> <bundle.json> | higgs join accept <bundle.json> <key.json> | higgs zone show <zone> | higgs record put <zone> <key> <value> [type] | higgs verify [chain] <zone> | higgs sync status|serve|once <peer> | higgs db dump [zone] | higgs db stats")
}

func initRootState() error {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: higgscrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	state := &stateFile{
		ManagedZone:    zone.RootZone,
		RootPrivateKey: rootPriv,
		Network:        ns,
	}
	if err := saveState(state); err != nil {
		return err
	}
	path, err := configuredStatePath()
	if err != nil {
		return err
	}
	fmt.Printf("initialized root in %s\n", path)
	fmt.Printf("root public key: %s\n", hex.EncodeToString(rootPub))
	return nil
}

func initState(managedZone zone.ZonePath) error {
	if !managedZone.Valid() || managedZone == zone.RootZone {
		return fmt.Errorf("invalid managed zone: %s", managedZone)
	}

	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	zonePub, zonePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: higgscrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	chain := zoneChain(managedZone)
	for i, path := range chain {
		authority := &zone.ZoneAuthority{
			Zone:      path,
			Epoch:     1,
			Threshold: higgscrypto.SupportedThreshold,
			Keys: []zone.AuthorizedKey{{
				Key: zonePub,
				Capabilities: []zone.Capability{{
					Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate},
				}},
			}},
		}
		ns.Zones[path] = zone.NewZoneState(path, authority)

		parent := zone.RootZone
		signer := rootPriv
		if i > 0 {
			parent = chain[i-1]
			signer = zonePriv
		}
		delegation := &zone.Delegation{
			ZoneName:  path,
			Scope:     zone.DelegationScopeDirectChild,
			Authority: *authority,
		}
		if err := higgscrypto.SignDelegation(delegation, parent, signer); err != nil {
			return err
		}
		ns.Zones[parent].Delegations[path] = delegation
	}

	state := &stateFile{
		ManagedZone:    managedZone,
		RootPrivateKey: rootPriv,
		ZonePrivateKey: zonePriv,
		Network:        ns,
	}
	if err := saveState(state); err != nil {
		return err
	}
	path, err := configuredStatePath()
	if err != nil {
		return err
	}
	fmt.Printf("initialized %s in %s\n", managedZone, path)
	fmt.Printf("root public key: %s\n", hex.EncodeToString(rootPub))
	return nil
}

func showZone(path zone.ZonePath) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	zs := state.Network.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(zs)
}

func putRecord(path zone.ZonePath, key string, value []byte, recordType string) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	configureValidation(state.Network)

	zs := state.Network.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	current := zs.Records[key]
	record := &zone.Record{
		Zone:      path,
		Key:       key,
		Type:      recordType,
		Value:     value,
		Version:   1,
		Timestamp: time.Now().Unix(),
	}
	if current != nil {
		record.Version = current.Version + 1
		record.PrevHash = higgscrypto.RecordHash(current)
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		return err
	}
	if err := state.Network.Put(record); err != nil {
		return err
	}
	if err := saveState(state); err != nil {
		return err
	}
	fmt.Printf("put %s/%s version %d\n", path, key, record.Version)
	return nil
}

func verifyChain(path zone.ZonePath) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	configureValidation(state.Network)
	if err := higgscrypto.VerifyChain(state.Network, path, time.Now()); err != nil {
		return err
	}
	fmt.Printf("verified chain for %s\n", path)
	return nil
}

func runDB(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "dump":
		filter := ""
		if len(args) == 2 {
			filter = args[1]
		}
		if len(args) > 2 {
			return usage()
		}
		return dbDump(filter)
	case "stats":
		if len(args) != 1 {
			return usage()
		}
		return dbStats()
	default:
		return usage()
	}
}

func dbDump(filter string) error {
	path, err := configuredStatePath()
	if err != nil {
		return err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return err
	}
	defer db.Close()

	return db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			bucketName := string(name)
			if filter != "" {
				if bucketName == "_meta" {
					// keep meta bucket even when filtering
				} else if bucketName != "zone:"+filter {
					return nil
				}
			}
			fmt.Printf("bucket: %s\n", bucketName)
			return b.ForEach(func(k, v []byte) error {
				fmt.Printf("  key: %s\n", string(k))
				var data any
				if err := json.Unmarshal(v, &data); err == nil {
					pretty, _ := json.MarshalIndent(data, "    ", "  ")
					fmt.Printf("    value (json):\n%s\n", pretty)
				} else {
					s := string(v)
					if len(s) > 200 {
						s = s[:200] + "..."
					}
					fmt.Printf("    value (raw): %s\n", s)
				}
				return nil
			})
		})
	})
}

func dbStats() error {
	path, err := configuredStatePath()
	if err != nil {
		return err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return err
	}
	defer db.Close()

	var totalBuckets, totalKeys int
	var totalSize int64

	err = db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			totalBuckets++
			bucketName := string(name)
			bucketKeys := 0
			var bucketSize int64
			b.ForEach(func(k, v []byte) error {
				totalKeys++
				bucketKeys++
				bucketSize += int64(len(k)) + int64(len(v))
				return nil
			})
			totalSize += bucketSize
			fmt.Printf("bucket %-20s keys=%4d size=%8d bytes\n", bucketName+":", bucketKeys, bucketSize)
			return nil
		})
	})
	if err != nil {
		return err
	}
	fmt.Printf("%-27s keys=%4d size=%8d bytes\n", "total:", totalKeys, totalSize)
	return nil
}

func runSync(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "status":
		return syncStatus()
	case "serve":
		return syncServe()
	case "once":
		if len(args) != 2 {
			return usage()
		}
		return syncOnce(args[1])
	default:
		return usage()
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

func defaultPeerID(state *stateFile) string {
	if state == nil || len(state.ZonePrivateKey) == 0 {
		return "local"
	}
	pub := state.ZonePrivateKey.Public().(ed25519.PublicKey)
	return hex.EncodeToString(higgscrypto.KeyID(pub))[:16]
}

func countPending(zs *zone.ZoneState) int {
	if zs == nil {
		return 0
	}
	var out int
	for _, records := range zs.PendingRecords {
		out += len(records)
	}
	return out
}

func totalPending(ns *zone.NetworkState) int {
	if ns == nil {
		return 0
	}
	var out int
	for _, zs := range ns.Zones {
		out += countPending(zs)
	}
	return out
}

func globalRootHash(digests []gossip.ZoneDigest) []byte {
	parts := make([][]byte, 0, len(digests)*2)
	for _, digest := range digests {
		parts = append(parts, []byte(digest.Zone), digest.RootHash)
	}
	return higgscrypto.Hash(parts...)
}

func recordPeerSync(state *stateFile, peerID string, err error) {
	if state == nil || peerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	peerState.LastSyncUnix = time.Now().Unix()
	if err != nil {
		peerState.LastError = err.Error()
	} else {
		peerState.LastError = ""
	}
	state.SyncPeers[peerID] = peerState
}

func normalizeSyncPeers(state *stateFile) {
	if state.SyncPeers == nil {
		state.SyncPeers = make(map[string]syncPeerState)
	}
}

func loadState() (*stateFile, error) {
	path, err := configuredStatePath()
	if err != nil {
		return nil, err
	}
	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		return nil, err
	}
	defer store.Close()

	ns, err := store.LoadNetwork()
	if err != nil {
		return nil, err
	}
	var meta stateMeta
	if err := store.LoadMetaJSON(cliMetaKey, &meta); err != nil {
		return nil, err
	}
	state := stateFile{
		ManagedZone:    meta.ManagedZone,
		RootPrivateKey: meta.RootPrivateKey,
		ZonePrivateKey: meta.ZonePrivateKey,
		Network:        ns,
		SyncPeers:      meta.SyncPeers,
	}
	if state.Network == nil || len(state.Network.Zones) == 0 {
		return nil, errors.New("state file has no network")
	}
	normalizeState(state.Network)
	normalizeSyncPeers(&state)
	if err := verifyConfiguredRootTrust(state.Network); err != nil {
		return nil, err
	}
	return &state, nil
}

func saveState(state *stateFile) error {
	path, err := configuredStatePath()
	if err != nil {
		return err
	}
	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		return err
	}
	defer store.Close()

	meta := stateMeta{
		ManagedZone:    state.ManagedZone,
		RootPrivateKey: state.RootPrivateKey,
		ZonePrivateKey: state.ZonePrivateKey,
		SyncPeers:      state.SyncPeers,
	}
	if err := store.SaveMetaJSON(cliMetaKey, &meta); err != nil {
		return err
	}
	return store.SaveNetwork(state.Network)
}

func zoneChain(path zone.ZonePath) []zone.ZonePath {
	ancestors := path.Ancestors()
	out := make([]zone.ZonePath, 0, len(ancestors)-1)
	for i := len(ancestors) - 2; i >= 0; i-- {
		out = append(out, ancestors[i])
	}
	return out
}

func verifyConfiguredRootTrust(ns *zone.NetworkState) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	if len(config.TrustedRootPublicKey) == 0 {
		return nil
	}
	root := ns.Zones[zone.RootZone]
	if root == nil || root.Authority == nil {
		return errors.New("trusted root public key configured but root authority is missing")
	}
	for _, key := range root.Authority.Keys {
		if equalPublicKey(key.Key, config.TrustedRootPublicKey) {
			return nil
		}
	}
	return errors.New("root authority does not match trusted_root_public_key in config.yaml")
}

func equalPublicKey(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	var out byte
	for i := range a {
		out |= a[i] ^ b[i]
	}
	return out == 0
}

func configureValidation(ns *zone.NetworkState) {
	ns.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
}

func normalizeState(ns *zone.NetworkState) {
	if ns.Zones == nil {
		ns.Zones = make(map[zone.ZonePath]*zone.ZoneState)
	}
	for path, zs := range ns.Zones {
		if zs.Path == "" {
			zs.Path = path
		}
		if zs.Delegations == nil {
			zs.Delegations = make(map[zone.ZonePath]*zone.Delegation)
		}
		if zs.Records == nil {
			zs.Records = make(map[string]*zone.Record)
		}
		if zs.RecordHistory == nil {
			zs.RecordHistory = make(map[string][]*zone.Record)
		}
		if zs.PendingRecords == nil {
			zs.PendingRecords = make(map[string][]*zone.Record)
		}
	}
}
