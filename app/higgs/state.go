package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	higgsstate "github.com/Catofes/higgs/internal/state"
	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
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
	IPsecTransportKey *ipsecTransportKeyState
	IPsecPortRecord   *ipsecPortRecordState
	LinkInstances     map[string]linkInstanceState
	IPsecReconcile    *ipsecReconcileState
	RoutingReconcile  *routingReconcileState
	FirewallReconcile *firewallReconcileState
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

func tryStateRLockWithin(state *stateFile, timeout time.Duration) (func(), bool) {
	if state == nil {
		return func() {}, true
	}
	if state.mu.TryRLock() {
		return state.RUnlock, true
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			return nil, false
		case <-ticker.C:
			if state.mu.TryRLock() {
				return state.RUnlock, true
			}
		}
	}
}

type stateMeta struct {
	ManagedZone       zone.ZonePath                 `json:"managed_zone"`
	IdentityKeyPath   string                        `json:"identity_key_path,omitempty"`
	RootPrivateKey    ed25519.PrivateKey            `json:"root_private_key"`
	ZonePrivateKey    ed25519.PrivateKey            `json:"zone_private_key"`
	SyncPeers         map[string]syncPeerState      `json:"sync_peers,omitempty"`
	IPsecTransportKey *ipsecTransportKeyState       `json:"ipsec_transport_key,omitempty"`
	IPsecPortRecord   *ipsecPortRecordState         `json:"ipsec_port_record,omitempty"`
	LinkInstances     map[string]linkInstanceState  `json:"link_instances,omitempty"`
	IPsecReconcile    *ipsecReconcileState          `json:"ipsec_reconcile,omitempty"`
	RoutingReconcile  *routingReconcileState        `json:"routing_reconcile,omitempty"`
	FirewallReconcile *firewallReconcileState       `json:"firewall_reconcile,omitempty"`
	BirdInstances     map[string]*BirdInstanceState `json:"bird_instances,omitempty"`
	Admission         *admissionState               `json:"admission,omitempty"`
}

type firewallReconcileState = higgsstate.FirewallReconcileState
type firewallInstanceReconcileStateEntry = higgsstate.FirewallReconcileInstance

type admissionState = higgsstate.AdmissionState

type BirdInstanceState = higgsstate.BirdInstanceState

func cloneBirdInstances(in map[string]*BirdInstanceState) map[string]*BirdInstanceState {
	if in == nil {
		return nil
	}
	out := make(map[string]*BirdInstanceState, len(in))
	for id, inst := range in {
		if inst == nil {
			continue
		}
		copyInst := *inst
		if inst.Overlays != nil {
			copyInst.Overlays = append([]string(nil), inst.Overlays...)
		}
		out[id] = &copyInst
	}
	return out
}

type routingReconcileState = higgsstate.RoutingReconcileState

func cloneFirewallReconcileState(in *firewallReconcileState) *firewallReconcileState {
	if in == nil {
		return nil
	}
	out := *in
	if in.Instances != nil {
		out.Instances = make(map[string]*firewallInstanceReconcileStateEntry, len(in.Instances))
		for id, entry := range in.Instances {
			if entry == nil {
				continue
			}
			copyEntry := *entry
			out.Instances[id] = &copyEntry
		}
	}
	return &out
}

type ipsecTransportKeyState = higgsstate.IPsecTransportKeyState
type ipsecPortRecordState = higgsstate.IPsecPortRecordState

type linkInstanceState = higgsstate.LinkInstanceState
type linkOwnerState = higgsstate.LinkOwnerState

type ipsecReconcileState = higgsstate.IPsecReconcileState
type desiredLinkState = higgsstate.DesiredLinkState
type linkSAState = higgsstate.LinkSAState
type linkActionState = higgsstate.LinkActionState
type linkSkipState = higgsstate.LinkSkipState

type syncPeerState = higgsstate.PeerRuntimeState
type observedGraceAddrState = higgsstate.PeerObservedGraceAddrState
type datagramStats = higgsstate.PeerDatagramStats
type objectPullStats = higgsstate.PeerObjectPullStats
type rejectedDigestState = higgsstate.PeerRejectedDigest

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
		IPsecTransportKey: meta.IPsecTransportKey,
		IPsecPortRecord:   meta.IPsecPortRecord,
		LinkInstances:     meta.LinkInstances,
		IPsecReconcile:    meta.IPsecReconcile,
		RoutingReconcile:  meta.RoutingReconcile,
		FirewallReconcile: meta.FirewallReconcile,
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

func saveStateAt(path string, state *stateFile) error {
	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		return err
	}
	defer store.Close()
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

	meta := stateMeta{
		ManagedZone:       state.ManagedZone,
		IdentityKeyPath:   state.IdentityKeyPath,
		RootPrivateKey:    state.RootPrivateKey,
		ZonePrivateKey:    state.ZonePrivateKey,
		SyncPeers:         state.SyncPeers,
		IPsecTransportKey: state.IPsecTransportKey,
		IPsecPortRecord:   state.IPsecPortRecord,
		LinkInstances:     state.LinkInstances,
		IPsecReconcile:    state.IPsecReconcile,
		RoutingReconcile:  state.RoutingReconcile,
		FirewallReconcile: state.FirewallReconcile,
		BirdInstances:     state.BirdInstances,
		Admission:         state.Admission,
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
