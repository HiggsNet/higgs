package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/observability"
	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	bolt "go.etcd.io/bbolt"
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
	if state == nil {
		return syncConfigFromAppConfig(rt.Config, nil), nil
	}
	return syncConfigFromAppConfig(rt.Config, &corestate.VerifiedState{
		ManagedZone:        state.ManagedZone,
		IdentityPrivateKey: append(ed25519.PrivateKey(nil), state.ZonePrivateKey...),
	}), nil
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
	partitioned, found, err := loadPartitionedState(path, config)
	if err != nil {
		return nil, err
	}
	if found {
		return partitioned, nil
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

func loadPartitionedState(path string, config *appConfig) (*stateFile, bool, error) {
	store, err := corestate.OpenBoltStore(path, 0o600, daemonBoltLockTimeout)
	if err != nil {
		return nil, false, err
	}
	var snapshot linuxStateSnapshot
	var found bool
	loadErr := store.View(func(tx *bolt.Tx) error {
		var err error
		snapshot, found, err = loadLinuxStateTx(tx)
		return err
	})
	closeErr := store.Close()
	if loadErr != nil {
		return nil, false, loadErr
	}
	if closeErr != nil {
		return nil, false, closeErr
	}
	if !found {
		return nil, false, nil
	}
	common, err := corestate.RestoreStore(snapshot.Candidate, snapshot.Revision, nil)
	if err != nil {
		return nil, false, err
	}
	combined, err := NewDaemonStateStore(common, snapshot.Runtime)
	if err != nil {
		return nil, false, err
	}
	state, _ := combined.Snapshot()
	if err := verifyConfiguredRootTrustAt(state.Network, config.TrustedRootPublicKey); err != nil {
		return nil, false, err
	}
	if err := applyConfiguredIdentityOverlay(state, config); err != nil {
		return nil, false, err
	}
	return state, true, nil
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

func stateMetaFromState(state *stateFile) stateMeta {
	if state == nil {
		return stateMeta{}
	}
	return stateMeta{
		ManagedZone:       state.ManagedZone,
		IdentityKeyPath:   state.IdentityKeyPath,
		RootPrivateKey:    state.RootPrivateKey,
		ZonePrivateKey:    state.ZonePrivateKey,
		SyncPeers:         state.SyncPeers,
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

func sameStateFileInfo(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) &&
		a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func verifyConfiguredRootTrustAt(ns *zone.NetworkState, trustRoot ed25519.PublicKey) error {
	if len(trustRoot) == 0 {
		return nil
	}
	return photoncrypto.VerifyPinnedRoot(ns, trustRoot)
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

func defaultPeerID(verified *corestate.VerifiedState) string {
	if verified == nil {
		return "local"
	}
	if verified.ManagedZone != "" && verified.ManagedZone != zone.RootZone {
		return string(verified.ManagedZone)
	}
	if len(verified.IdentityPrivateKey) == 0 {
		return "local"
	}
	pub := verified.IdentityPrivateKey.Public().(ed25519.PublicKey)
	return hex.EncodeToString(photoncrypto.KeyID(pub))[:16]
}

func timeNow() time.Time {
	return time.Now()
}

func globalRootHash(digests []corestate.ZoneDigest) []byte {
	parts := make([][]byte, 0, len(digests)*2)
	for _, digest := range digests {
		parts = append(parts, []byte(digest.Zone), digest.RootHash)
	}
	return photoncrypto.Hash(parts...)
}

func recordSyncActivePull(store *observability.PeerObservabilityStore, peerID, event string, session *gossip.SyncSession, now time.Time) {
	store.Update(peerID, now, func(snapshot *observability.PeerDiagnostics) {
		if session != nil {
			snapshot.ActivePullState = string(session.State)
		} else {
			snapshot.ActivePullState = ""
		}
		snapshot.ActivePullLastEvent = event
		snapshot.ActivePullUpdatedUnix = now.Unix()
	})
}

func recordSyncHint(store *observability.PeerObservabilityStore, peerID, reason, suppression string, accepted bool, now time.Time) {
	store.Update(peerID, now, func(snapshot *observability.PeerDiagnostics) {
		if accepted {
			snapshot.HintAccepted++
			snapshot.LastHintSuppression = ""
		} else {
			snapshot.HintSuppressed++
			snapshot.LastHintSuppression = suppression
		}
		snapshot.LastHintUnix = now.Unix()
		snapshot.LastHintReason = reason
	})
}

func recordReadOnlyResponder(store *observability.PeerObservabilityStore, peerID, kind string, zoneName zone.ZonePath, now time.Time) {
	store.Update(peerID, now, func(snapshot *observability.PeerDiagnostics) {
		snapshot.ReadOnlyResponder++
		snapshot.LastResponderUnix = now.Unix()
		snapshot.LastResponderKind = kind
		snapshot.LastResponderZone = string(zoneName)
	})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
