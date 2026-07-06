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
	"github.com/Catofes/higgs/pkg/routing/bird"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
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

// firewallReconcileState persists firewall reconcile diagnostics per instance.
type firewallReconcileState struct {
	Backend     string                                          `json:"backend,omitempty"`
	Instances   map[string]*firewallInstanceReconcileStateEntry `json:"instances,omitempty"`
	LastRunUnix int64                                           `json:"last_run_unix,omitempty"`
	LastError   string                                          `json:"last_error,omitempty"`
}

type firewallInstanceReconcileStateEntry struct {
	Generation   uint64 `json:"generation,omitempty"`
	LastRunUnix  int64  `json:"last_run_unix,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	PolicyHash   string `json:"policy_hash,omitempty"`
	OwnedObjects int    `json:"owned_objects,omitempty"`
}

// admissionState tracks auto-join admission diagnostics. It is persisted so
// that pending reasons survive daemon restarts and operators can inspect
// why a node has not yet been adopted.
type admissionState struct {
	// Pending is true when the node is waiting for delegation adoption.
	Pending bool `json:"pending,omitempty"`
	// PendingSinceUnix is when the node first entered pending state.
	PendingSinceUnix int64 `json:"pending_since_unix,omitempty"`
	// AdoptedAtUnix is when the node was most recently adopted (0 = never).
	AdoptedAtUnix int64 `json:"adopted_at_unix,omitempty"`
	// LastAdoptionError records the most recent adoption failure.
	LastAdoptionError string `json:"last_adoption_error,omitempty"`
	// LastBootstrapSyncUnix tracks the most recent successful bootstrap peer
	// sync round while pending (0 = never synced).
	LastBootstrapSyncUnix int64 `json:"last_bootstrap_sync_unix,omitempty"`
	// JoinRequestB64 is the base64-encoded join request that the parent zone
	// admin needs to sign a delegation for.
	JoinRequestB64 string `json:"join_request_b64,omitempty"`
	// PendingReason is the structured diagnostic reason for the current
	// pending state (e.g. missing_parent_zone, missing_delegation,
	// delegation_key_mismatch, verify_chain_failed, no_bootstrap_sync).
	PendingReason string `json:"pending_reason,omitempty"`
	// PendingReasonDetail provides additional context for the pending reason.
	PendingReasonDetail string `json:"pending_reason_detail,omitempty"`
}

type BirdInstanceState struct {
	NetNSName        string                 `json:"netns_name"`
	Overlays         []string               `json:"overlays,omitempty"`
	ConfigPath       string                 `json:"config_path"`
	ControlSocket    string                 `json:"control_socket"`
	PIDFile          string                 `json:"pid_file"`
	RouterID         uint32                 `json:"router_id"`
	Owner            bird.BirdResourceOwner `json:"owner,omitempty"`
	LastConfigHash   string                 `json:"last_config_hash"`
	LastError        string                 `json:"last_error"`
	LastExit         string                 `json:"last_exit,omitempty"`
	FailureCount     int                    `json:"failure_count,omitempty"`
	BackoffUntilUnix int64                  `json:"backoff_until_unix,omitempty"`
	State            string                 `json:"state"` // pending, running, degraded, error
}

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

type routingReconcileState struct {
	LastRunUnix int64  `json:"last_run_unix,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

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

type ipsecTransportKeyState struct {
	Kind        string `json:"kind,omitempty"`
	Algorithm   string `json:"algorithm,omitempty"`
	PublicKey   []byte `json:"public_key,omitempty"`
	PrivateKey  []byte `json:"private_key,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	NotBefore   int64  `json:"not_before,omitempty"`
	NotAfter    int64  `json:"not_after,omitempty"`
	UpdatedAt   int64  `json:"updated_at,omitempty"`
}

type ipsecPortRecordState struct {
	Mode       string           `json:"mode,omitempty"`
	Range      *ipsec.PortRange `json:"range,omitempty"`
	Generation uint64           `json:"generation,omitempty"`
	UpdatedAt  int64            `json:"updated_at,omitempty"`
}

type linkInstanceState struct {
	ID                    string         `json:"id"`
	GroupID               string         `json:"group_id,omitempty"`
	PeerZone              zone.ZonePath  `json:"peer_zone"`
	TransportKind         string         `json:"transport_kind,omitempty"`
	LinkID                string         `json:"link_id,omitempty"`
	PathKey               string         `json:"path_key,omitempty"`
	TransportID           string         `json:"transport_id,omitempty"`
	DesiredSpecHash       string         `json:"desired_spec_hash,omitempty"`
	ActualState           string         `json:"actual_state,omitempty"`
	InterfaceName         string         `json:"interface_name,omitempty"`
	XFRMIfID              uint32         `json:"xfrm_if_id,omitempty"`
	LocalTunnelAddr       string         `json:"local_tunnel_addr,omitempty"`
	PeerTunnelAddr        string         `json:"peer_tunnel_addr,omitempty"`
	IKEName               string         `json:"ike_name,omitempty"`
	ChildSAName           string         `json:"child_sa_name,omitempty"`
	Endpoint              string         `json:"endpoint,omitempty"`
	RemoteGeneration      uint64         `json:"remote_generation,omitempty"`
	StagedGeneration      uint64         `json:"staged_generation,omitempty"`
	RotatePhase           string         `json:"rotate_phase,omitempty"`
	StagedIKEName         string         `json:"staged_ike_name,omitempty"`
	StagedChildSAName     string         `json:"staged_child_sa_name,omitempty"`
	StagedInterfaceName   string         `json:"staged_interface_name,omitempty"`
	StagedXFRMIfID        uint32         `json:"staged_xfrm_if_id,omitempty"`
	StagedLocalTunnelAddr string         `json:"staged_local_tunnel_addr,omitempty"`
	StagedPeerTunnelAddr  string         `json:"staged_peer_tunnel_addr,omitempty"`
	RotateDeadline        int64          `json:"rotate_deadline,omitempty"`
	LastError             string         `json:"last_error,omitempty"`
	FailureCount          int            `json:"failure_count,omitempty"`
	BackoffUntil          int64          `json:"backoff_until,omitempty"`
	LastTransition        int64          `json:"last_transition,omitempty"`
	Owner                 linkOwnerState `json:"owner,omitempty"`

	// Phase 4.5 bidirectional takeover state.
	InitiatorRole     string `json:"initiator_role,omitempty"`
	TakeoverPhase     string `json:"takeover_phase,omitempty"`
	TakeoverStartedAt int64  `json:"takeover_started_at,omitempty"`
	TakeoverUntil     int64  `json:"takeover_until,omitempty"`
	LastTakeoverError string `json:"last_takeover_error,omitempty"`
	ObservedInitiator string `json:"observed_initiator,omitempty"`
}

type linkOwnerState struct {
	Manager     string `json:"manager,omitempty"`
	GroupID     string `json:"group_id,omitempty"`
	InstanceID  string `json:"instance_id,omitempty"`
	LinkID      string `json:"link_id,omitempty"`
	TransportID string `json:"transport_id,omitempty"`
	Token       string `json:"token,omitempty"`
}

type ipsecReconcileState struct {
	LastRunUnix    int64              `json:"last_run_unix,omitempty"`
	SourceRevision uint64             `json:"source_revision,omitempty"`
	Committed      bool               `json:"committed,omitempty"`
	Stale          bool               `json:"stale,omitempty"`
	DesiredLinks   int                `json:"desired_links,omitempty"`
	Desired        []desiredLinkState `json:"desired,omitempty"`
	ActualSAs      []linkSAState      `json:"actual_sas,omitempty"`
	Actions        []linkActionState  `json:"actions,omitempty"`
	Skipped        []linkSkipState    `json:"skipped,omitempty"`
	LastError      string             `json:"last_error,omitempty"`
}

type desiredLinkState struct {
	InstanceID      string        `json:"instance_id,omitempty"`
	GroupID         string        `json:"group_id,omitempty"`
	PeerZone        zone.ZonePath `json:"peer_zone,omitempty"`
	LinkID          string        `json:"link_id,omitempty"`
	PathKey         string        `json:"path_key,omitempty"`
	TransportID     string        `json:"transport_id,omitempty"`
	DesiredSpecHash string        `json:"desired_spec_hash,omitempty"`
	InterfaceName   string        `json:"interface_name,omitempty"`
	XFRMIfID        uint32        `json:"xfrm_if_id,omitempty"`
	Endpoint        string        `json:"endpoint,omitempty"`
	LocalTunnelAddr string        `json:"local_tunnel_addr,omitempty"`
	PeerTunnelAddr  string        `json:"peer_tunnel_addr,omitempty"`
}

type linkSAState struct {
	Name           string `json:"name,omitempty"`
	Peer           string `json:"peer,omitempty"`
	ChildSA        string `json:"child_sa,omitempty"`
	IKEState       string `json:"ike_state,omitempty"`
	ChildState     string `json:"child_state,omitempty"`
	XFRMIfID       uint32 `json:"xfrm_if_id,omitempty"`
	ReqID          uint32 `json:"reqid,omitempty"`
	LocalIdentity  string `json:"local_identity,omitempty"`
	RemoteIdentity string `json:"remote_identity,omitempty"`
	LocalEndpoint  string `json:"local_endpoint,omitempty"`
	RemoteEndpoint string `json:"remote_endpoint,omitempty"`
	Endpoint       string `json:"endpoint,omitempty"`
	Established    bool   `json:"established,omitempty"`
}

type linkActionState struct {
	Action     string        `json:"action"`
	InstanceID string        `json:"instance_id,omitempty"`
	GroupID    string        `json:"group_id,omitempty"`
	PeerZone   zone.ZonePath `json:"peer_zone,omitempty"`
	Reason     string        `json:"reason,omitempty"`
}

type linkSkipState struct {
	GroupID string        `json:"group_id,omitempty"`
	Peer    zone.ZonePath `json:"peer,omitempty"`
	Reason  string        `json:"reason,omitempty"`
	Detail  string        `json:"detail,omitempty"`
}

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
