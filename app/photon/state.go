package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

const cliMetaKey = "cli_state"

type stateFile struct {
	mu                sync.RWMutex       `json:"-"`
	ManagedZone       zone.ZonePath      `json:"managed_zone"`
	IdentityKeyPath   string             `json:"identity_key_path,omitempty"`
	RootPrivateKey    ed25519.PrivateKey `json:"root_private_key"`
	ZonePrivateKey    ed25519.PrivateKey `json:"zone_private_key"`
	Network           *zone.NetworkState `json:"network"`
	SyncPeers         map[string]syncPeerState
	PeerCleanups      map[string]peerLifecycleCleanupState
	IPsecTransportKey *ipsecTransportKeyState
	IPsecPortRecord   *ipsecPortRecordState
	LinkInstances     map[string]linkInstanceState
	IPsecReconcile    *ipsecReconcileState
	RoutingReconcile  *routingReconcileState
	FirewallReconcile *firewallReconcileState
	EndpointACLs      map[string]endpointACL
	BirdInstances     map[string]*BirdInstanceState
	Admission         *admissionState `json:"admission,omitempty"`
}

// Lock acquires the write lock for this state file. All state mutations must
// be performed while holding the write lock.
func (s *stateFile) Lock() {
	s.mu.Lock()
}

// Unlock releases the write lock for this state file.
func (s *stateFile) Unlock() {
	s.mu.Unlock()
}

// RLock acquires the read lock for this state file. All reads of mutable
// state fields from non-event-loop goroutines must hold the read lock.
func (s *stateFile) RLock() {
	s.mu.RLock()
}

// RUnlock releases the read lock for this state file.
func (s *stateFile) RUnlock() {
	s.mu.RUnlock()
}

// WithLock runs fn while holding the write lock.
func (s *stateFile) WithLock(fn func()) {
	s.Lock()
	defer s.Unlock()
	fn()
}

// WithRLock runs fn while holding the read lock.
func (s *stateFile) WithRLock(fn func()) {
	s.RLock()
	defer s.RUnlock()
	fn()
}

type stateMeta struct {
	ManagedZone       zone.ZonePath                        `json:"managed_zone"`
	IdentityKeyPath   string                               `json:"identity_key_path,omitempty"`
	RootPrivateKey    ed25519.PrivateKey                   `json:"root_private_key"`
	ZonePrivateKey    ed25519.PrivateKey                   `json:"zone_private_key"`
	SyncPeers         map[string]syncPeerState             `json:"sync_peers,omitempty"`
	PeerCleanups      map[string]peerLifecycleCleanupState `json:"peer_cleanups,omitempty"`
	IPsecTransportKey *ipsecTransportKeyState              `json:"ipsec_transport_key,omitempty"`
	IPsecPortRecord   *ipsecPortRecordState                `json:"ipsec_port_record,omitempty"`
	LinkInstances     map[string]linkInstanceState         `json:"link_instances,omitempty"`
	IPsecReconcile    *ipsecReconcileState                 `json:"ipsec_reconcile,omitempty"`
	RoutingReconcile  *routingReconcileState               `json:"routing_reconcile,omitempty"`
	FirewallReconcile *firewallReconcileState              `json:"firewall_reconcile,omitempty"`
	EndpointACLs      map[string]endpointACL               `json:"endpoint_acls,omitempty"`
	BirdInstances     map[string]*BirdInstanceState        `json:"bird_instances,omitempty"`
	Admission         *admissionState                      `json:"admission,omitempty"`
}

type firewallReconcileState = photonstate.FirewallReconcileState
type firewallInstanceReconcileStateEntry = photonstate.FirewallReconcileInstance
type endpointACL = photonstate.EndpointACL

type admissionState = photonstate.AdmissionState

type BirdInstanceState = photonstate.BirdInstanceState

func cloneBirdInstances(in map[string]*BirdInstanceState) map[string]*BirdInstanceState {
	if in == nil {
		return nil
	}
	out := make(map[string]*BirdInstanceState, len(in))
	for id, inst := range in {
		out[id] = cloneBirdInstance(inst)
	}
	return out
}

func cloneBirdInstance(inst *BirdInstanceState) *BirdInstanceState {
	if inst == nil {
		return nil
	}
	out := *inst
	if inst.Overlays != nil {
		out.Overlays = make([]string, len(inst.Overlays))
		copy(out.Overlays, inst.Overlays)
	}
	return &out
}

type routingReconcileState = photonstate.RoutingReconcileState

func cloneFirewallReconcileState(in *firewallReconcileState) *firewallReconcileState {
	if in == nil {
		return nil
	}
	out := *in
	if in.Instances != nil {
		out.Instances = make(map[string]*firewallInstanceReconcileStateEntry, len(in.Instances))
		for id, entry := range in.Instances {
			if entry == nil {
				out.Instances[id] = nil
				continue
			}
			copyEntry := *entry
			out.Instances[id] = &copyEntry
		}
	}
	return &out
}

type ipsecTransportKeyState = photonstate.IPsecTransportKeyState
type ipsecPortRecordState = photonstate.IPsecPortRecordState

type linkInstanceState = photonstate.LinkInstanceState
type linkOwnerState = photonstate.LinkOwnerState

type ipsecReconcileState = photonstate.IPsecReconcileState
type desiredLinkState = photonstate.DesiredLinkState
type linkSAState = photonstate.LinkSAState
type linkActionState = photonstate.LinkActionState
type linkSkipState = photonstate.LinkSkipState

type syncPeerState = photonstate.PeerRuntimeState
type observedGraceAddrState = photonstate.PeerObservedGraceAddrState
type datagramStats = photonstate.PeerDatagramStats
type objectPullStats = photonstate.PeerObjectPullStats
type rejectedDigestState = photonstate.PeerRejectedDigest

// peerLifecycleCleanupState is a local, persisted suppression marker. It is
// deliberately separate from SyncPeers so cleanup_after can remove the peer
// cache without allowing still-valid, stale Zone records to recreate data-plane
// links before the peer has successfully synchronized again.
type peerLifecycleCleanupState struct {
	LastActiveUnix int64  `json:"last_active_unix,omitempty"`
	CleanupUnix    int64  `json:"cleanup_unix"`
	Reason         string `json:"reason"`
}

type syncConfigFile struct {
	PeerID                 string           `json:"peer_id"`
	ListenAddr             string           `json:"listen_addr"`
	Bootstrap              []syncConfigPeer `json:"bootstrap"`
	MaxMessageBytes        int              `json:"max_message_bytes"`
	MaxSyncZones           int              `json:"max_sync_zones"`
	MaxSyncRecords         int              `json:"max_sync_records"`
	LogLevel               string           `json:"log_level,omitempty"`
	LogMode                string           `json:"log_mode,omitempty"`
	LogFile                string           `json:"log_file,omitempty"`
	AdvertiseAddrs         []string         `json:"advertise_addrs,omitempty"`
	Reflectors             []string         `json:"reflectors,omitempty"`
	ReflectorInterval      time.Duration    `json:"reflector_interval,omitempty"`
	ReflectorTimeout       time.Duration    `json:"reflector_timeout,omitempty"`
	EndpointTTL            time.Duration    `json:"endpoint_ttl,omitempty"`
	EndpointRefresh        time.Duration    `json:"endpoint_refresh,omitempty"`
	EndpointGrace          time.Duration    `json:"endpoint_grace,omitempty"`
	DisableEndpointPublish bool             `json:"disable_endpoint_publish,omitempty"`
	EndpointDiscovery      string           `json:"endpoint_discovery,omitempty"`
	EndpointSourceOrder    []string         `json:"endpoint_source_order,omitempty"`
	FilterPrivateIPv4      bool             `json:"filter_private_ipv4,omitempty"`
}

type syncConfigPeer struct {
	ID   string `json:"id" yaml:"id"`
	Addr string `json:"addr" yaml:"addr"`
}

type Runtime struct {
	Config         *appConfig
	StatePath      string
	Clock          func() time.Time
	DisableControl bool
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
	return loadStateAtWithConfig(rt.StatePath, rt.Config)
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

func loadStateAtWithConfig(path string, config *appConfig) (*stateFile, error) {
	if config == nil {
		config = defaultAppConfig()
	}
	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if store != nil {
			_ = store.Close()
		}
	}()

	ns, err := store.LoadNetwork()
	if err != nil {
		return nil, err
	}
	var meta stateMeta
	if err := store.LoadMetaJSON(cliMetaKey, &meta); err != nil {
		return nil, err
	}
	state := stateFile{
		ManagedZone:       meta.ManagedZone,
		IdentityKeyPath:   meta.IdentityKeyPath,
		RootPrivateKey:    meta.RootPrivateKey,
		ZonePrivateKey:    meta.ZonePrivateKey,
		Network:           ns,
		SyncPeers:         meta.SyncPeers,
		PeerCleanups:      meta.PeerCleanups,
		IPsecTransportKey: meta.IPsecTransportKey,
		IPsecPortRecord:   meta.IPsecPortRecord,
		LinkInstances:     meta.LinkInstances,
		IPsecReconcile:    meta.IPsecReconcile,
		RoutingReconcile:  meta.RoutingReconcile,
		FirewallReconcile: meta.FirewallReconcile,
		EndpointACLs:      meta.EndpointACLs,
		BirdInstances:     meta.BirdInstances,
		Admission:         meta.Admission,
	}
	if state.Network == nil || len(state.Network.Zones) == 0 {
		if err := store.Close(); err != nil {
			return nil, err
		}
		store = nil
		state, err := createConfiguredBootstrapState(path, config)
		if err != nil {
			return nil, err
		}
		return state, nil
	}
	normalizeState(state.Network)
	normalizeSyncPeers(&state)
	if err := verifyConfiguredRootTrustAt(state.Network, config.TrustedRootPublicKey); err != nil {
		return nil, err
	}
	if err := applyConfiguredIdentityOverlay(&state, config); err != nil {
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

func saveStateMeta(state *stateFile) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	_, err = saveStateMetaAtWithFileInfo(rt.StatePath, state)
	return err
}

func saveStateAt(path string, state *stateFile) error {
	_, err := saveStateAtWithFileInfo(path, state)
	return err
}

// saveStateAtWithFileInfo returns a stable file marker only after the Bolt
// transactions and Close have succeeded. A stat failure or a file change
// between the final transaction and close does not fail the save; it merely
// leaves the marker unavailable so the daemon reloads conservatively.
func saveStateAtWithFileInfo(path string, state *stateFile) (os.FileInfo, error) {
	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		return nil, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = store.Close()
		}
	}()
	if state != nil && state.Network != nil && state.ManagedZone.Valid() {
		if zs := state.Network.Zones[state.ManagedZone]; zs != nil {
			logger := newAppLogger(nil)
			logger.Debug("state", "save", map[string]any{
				"path":         path,
				"managed_zone": state.ManagedZone.String(),
				"records":      len(zs.Records),
			})
		}
	}

	if err := store.SaveNetworkAndMetaJSON(cliMetaKey, stateMetaFromState(state), state.Network); err != nil {
		return nil, err
	}
	return closeStateStoreWithFileInfo(path, store, &closed)
}

// saveStateMetaAtWithFileInfo persists daemon-local runtime/configuration
// metadata without rewriting the immutable zone Network.
func saveStateMetaAtWithFileInfo(path string, state *stateFile) (os.FileInfo, error) {
	// A routing-only write may be the first persistence operation in tests,
	// recovery, or a freshly bootstrapped deployment. Seed the complete DB
	// before using the metadata-only fast path.
	if info, err := os.Stat(path); errors.Is(err, os.ErrNotExist) || (err == nil && info.Size() == 0) {
		return saveStateAtWithFileInfo(path, state)
	} else if err != nil {
		return nil, err
	}
	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		return nil, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = store.Close()
		}
	}()
	if err := store.SaveMetaJSON(cliMetaKey, stateMetaFromState(state)); err != nil {
		return nil, err
	}
	return closeStateStoreWithFileInfo(path, store, &closed)
}

func stateMetaFromState(state *stateFile) stateMeta {
	if state == nil {
		return stateMeta{}
	}
	return stateMeta{
		ManagedZone:       state.ManagedZone,
		IdentityKeyPath:   state.IdentityKeyPath,
		RootPrivateKey:    state.RootPrivateKey,
		ZonePrivateKey:    state.ZonePrivateKey,
		SyncPeers:         persistentSyncPeers(state.SyncPeers),
		PeerCleanups:      state.PeerCleanups,
		IPsecTransportKey: state.IPsecTransportKey,
		IPsecPortRecord:   state.IPsecPortRecord,
		LinkInstances:     state.LinkInstances,
		IPsecReconcile:    state.IPsecReconcile,
		RoutingReconcile:  state.RoutingReconcile,
		FirewallReconcile: state.FirewallReconcile,
		EndpointACLs:      state.EndpointACLs,
		BirdInstances:     state.BirdInstances,
		Admission:         state.Admission,
	}
}

func closeStateStoreWithFileInfo(path string, store *zone.BoltStore, closed *bool) (os.FileInfo, error) {
	beforeClose, beforeErr := os.Stat(path)
	if err := store.Close(); err != nil {
		*closed = true
		return nil, err
	}
	*closed = true
	afterClose, afterErr := os.Stat(path)
	if beforeErr != nil || afterErr != nil || !sameStateFileInfo(beforeClose, afterClose) {
		return nil, nil
	}
	return afterClose, nil
}

func persistentSyncPeers(peers map[string]syncPeerState) map[string]syncPeerState {
	if peers == nil {
		return nil
	}
	out := make(map[string]syncPeerState, len(peers))
	for peerID, peer := range peers {
		peer.DatagramStats = nil
		peer.ObjectPullStats = nil
		out[peerID] = peer
	}
	return out
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
	ns.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
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
		if zs.Revocations == nil {
			zs.Revocations = make(map[zone.ZonePath]*zone.DelegationRevocation)
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
	if state.PeerCleanups == nil {
		state.PeerCleanups = make(map[string]peerLifecycleCleanupState)
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
	return hex.EncodeToString(photoncrypto.KeyID(pub))[:16]
}

func timeNow() time.Time {
	return time.Now()
}

func globalRootHash(digests []gossip.ZoneDigest) []byte {
	parts := make([][]byte, 0, len(digests)*2)
	for _, digest := range digests {
		parts = append(parts, []byte(digest.Zone), digest.RootHash)
	}
	return photoncrypto.Hash(parts...)
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
		if peerState.ObservedAddr != "" && peerState.ObservedUntilUnix != 0 && now.Before(time.Unix(peerState.ObservedUntilUnix, 0)) {
			peerState.ObservedLastSyncUnix = now.Unix()
			peerState.ObservedFailureCount = 0
		}
	}
	state.SyncPeers[peerID] = peerState
}

func recordSyncActivePull(state *stateFile, peerID, event string, session *SyncSession, now time.Time) {
	if state == nil || peerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	if session != nil {
		peerState.ActivePullState = string(session.State)
	} else {
		peerState.ActivePullState = ""
	}
	peerState.ActivePullLastEvent = event
	peerState.ActivePullUpdatedUnix = now.Unix()
	state.SyncPeers[peerID] = peerState
}

func recordSyncHint(state *stateFile, peerID, reason, suppression string, accepted bool, now time.Time) {
	if state == nil || peerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	if accepted {
		peerState.HintAccepted++
		peerState.LastHintSuppression = ""
	} else {
		peerState.HintSuppressed++
		peerState.LastHintSuppression = suppression
	}
	peerState.LastHintUnix = now.Unix()
	peerState.LastHintReason = reason
	state.SyncPeers[peerID] = peerState
}

func recordReadOnlyResponder(state *stateFile, peerID, kind string, zoneName zone.ZonePath, now time.Time) {
	if state == nil || peerID == "" {
		return
	}
	normalizeSyncPeers(state)
	peerState := state.SyncPeers[peerID]
	peerState.ReadOnlyResponder++
	peerState.LastResponderUnix = now.Unix()
	peerState.LastResponderKind = kind
	peerState.LastResponderZone = string(zoneName)
	state.SyncPeers[peerID] = peerState
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
