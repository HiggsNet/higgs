package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

const cliMetaKey = "cli_state"

type stateFile struct {
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
