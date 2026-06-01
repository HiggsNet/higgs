package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
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
	LastSyncUnix          int64  `json:"last_sync_unix,omitempty"`
	LastAttemptUnix       int64  `json:"last_attempt_unix,omitempty"`
	BackoffUntilUnix      int64  `json:"backoff_until_unix,omitempty"`
	LastRelayUnix         int64  `json:"last_relay_unix,omitempty"`
	FailureCount          int    `json:"failure_count,omitempty"`
	LastError             string `json:"last_error,omitempty"`
	LastUpdateSource      string `json:"last_update_source,omitempty"`
	LastRelaySuppression  string `json:"last_relay_suppression,omitempty"`
	LastRelaySuppressedAt int64  `json:"last_relay_suppressed_at,omitempty"`
	DiscoveredAddr        string `json:"discovered_addr,omitempty"`
	DiscoveredAtUnix      int64  `json:"discovered_at_unix,omitempty"`
}

type syncConfigFile struct {
	PeerID            string           `json:"peer_id"`
	ListenAddr        string           `json:"listen_addr"`
	Bootstrap         []syncConfigPeer `json:"bootstrap"`
	MaxMessageBytes   int              `json:"max_message_bytes"`
	MaxSyncZones      int              `json:"max_sync_zones"`
	MaxSyncRecords    int              `json:"max_sync_records"`
	LogLevel          string           `json:"log_level,omitempty"`
	AdvertiseAddrs    []string         `json:"advertise_addrs,omitempty"`
	Reflectors        []string         `json:"reflectors,omitempty"`
	ReflectorInterval time.Duration    `json:"reflector_interval,omitempty"`
	EndpointTTL       time.Duration    `json:"endpoint_ttl,omitempty"`
	EndpointGrace     time.Duration    `json:"endpoint_grace,omitempty"`
}

type syncConfigPeer struct {
	ID   string `json:"id"`
	Addr string `json:"addr"`
}

type Runtime struct {
	Config    *appConfig
	StatePath string
	Clock     func() time.Time
}

func NewRuntime() (*Runtime, error) {
	config, err := loadAppConfig()
	if err != nil {
		return nil, err
	}
	path := config.StatePath
	if override := statePathOverride(); override != "" {
		path = override
	}
	return &Runtime{
		Config:    config,
		StatePath: path,
		Clock:     time.Now,
	}, nil
}

func (rt *Runtime) Now() time.Time {
	if rt != nil && rt.Clock != nil {
		return rt.Clock()
	}
	return time.Now()
}

func (rt *Runtime) LoadState() (*stateFile, error) {
	return loadStateAt(rt.StatePath, rt.Config.TrustedRootPublicKey)
}

func (rt *Runtime) SaveState(state *stateFile) error {
	return saveStateAt(rt.StatePath, state)
}

func (rt *Runtime) SyncConfig(state *stateFile) (*syncConfigFile, error) {
	return syncConfigFromAppConfig(rt.Config, state), nil
}

func (rt *Runtime) ConfigureNetworkValidation(ns *zone.NetworkState) {
	configureValidation(ns)
}

func loadState() (*stateFile, error) {
	rt, err := NewRuntime()
	if err != nil {
		return nil, err
	}
	return rt.LoadState()
}

func loadStateAt(path string, trustRoot ed25519.PublicKey) (*stateFile, error) {
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
	if err := verifyConfiguredRootTrustAt(state.Network, trustRoot); err != nil {
		return nil, err
	}
	return &state, nil
}

func saveState(state *stateFile) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	return rt.SaveState(state)
}

func saveStateAt(path string, state *stateFile) error {
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
	return verifyConfiguredRootTrustAt(ns, config.TrustedRootPublicKey)
}

func verifyConfiguredRootTrustAt(ns *zone.NetworkState, trustRoot ed25519.PublicKey) error {
	if len(trustRoot) == 0 {
		return nil
	}
	root := ns.Zones[zone.RootZone]
	if root == nil || root.Authority == nil {
		return errors.New("trusted root public key configured but root authority is missing")
	}
	for _, key := range root.Authority.Keys {
		if equalPublicKey(key.Key, trustRoot) {
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
	}
}

func normalizeSyncPeers(state *stateFile) {
	if state.SyncPeers == nil {
		state.SyncPeers = make(map[string]syncPeerState)
	}
}

func defaultPeerID(state *stateFile) string {
	if state == nil {
		return "local"
	}
	if state.ManagedZone != "" && state.ManagedZone != zone.RootZone {
		return string(state.ManagedZone)
	}
	if len(state.ZonePrivateKey) == 0 {
		return "local"
	}
	pub := state.ZonePrivateKey.Public().(ed25519.PublicKey)
	return hex.EncodeToString(higgscrypto.KeyID(pub))[:16]
}

func timeNow() time.Time {
	return time.Now()
}

func globalRootHash(digests []gossip.ZoneDigest) []byte {
	parts := make([][]byte, 0, len(digests)*2)
	for _, digest := range digests {
		parts = append(parts, []byte(digest.Zone), digest.RootHash)
	}
	return higgscrypto.Hash(parts...)
}

func recordPeerSync(state *stateFile, peerID string, err error) {
	recordPeerSyncAt(state, peerID, err, timeNow())
}

func recordPeerSyncAt(state *stateFile, peerID string, err error, now time.Time) {
	if state == nil || peerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	peerState.LastAttemptUnix = now.Unix()
	if err != nil {
		peerState.FailureCount++
		backoff := time.Duration(1<<minInt(peerState.FailureCount, 6)) * time.Second
		peerState.BackoffUntilUnix = now.Add(backoff).Unix()
		peerState.LastError = err.Error()
	} else {
		peerState.LastSyncUnix = now.Unix()
		peerState.BackoffUntilUnix = 0
		peerState.FailureCount = 0
		peerState.LastError = ""
	}
	state.SyncPeers[peerID] = peerState
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
