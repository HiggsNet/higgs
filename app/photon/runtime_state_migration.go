package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	bolt "go.etcd.io/bbolt"
)

const linuxRuntimeSchemaVersion uint64 = 1

var (
	bucketLegacyMeta   = []byte("_meta")
	bucketLinuxRuntime = []byte("photon:linux-runtime")
	keyRuntimeSchema   = []byte("schema-version")
	keyRuntimePayload  = []byte("payload")

	errLegacyStateConflict      = errors.New("legacy and common state representations coexist")
	errLinuxRuntimeStateCorrupt = errors.New("linux runtime state is corrupt")
)

// linuxRuntimeState contains only Linux controller/configuration state. The
// verified Network, local signing keys and gossip restart hints are owned by
// the public state buckets and are deliberately absent here.
type linuxRuntimeState struct {
	IdentityKeyPath   string                               `json:"identity_key_path,omitempty"`
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

type legacyStateMigrationReport struct {
	Gossip legacyGossipCheckpointReport
}

// migrateLegacyRuntimeStateTx atomically replaces the legacy _meta/cli_state
// plus zone:* representation with the common state buckets and one Linux
// runtime bucket. The caller owns tx and decides commit/rollback. This remains
// detached from the online loader until the single-writer cutover.
func migrateLegacyRuntimeStateTx(tx *bolt.Tx, trustedRoot ed25519.PublicKey) (legacyStateMigrationReport, bool, error) {
	var report legacyStateMigrationReport
	if tx == nil || !tx.Writable() {
		return report, false, errors.New("legacy state migration requires a writable bbolt transaction")
	}
	_, _, _, commonFound, err := corestate.LoadBoltState(tx)
	if err != nil {
		return report, false, err
	}
	legacyMeta := tx.Bucket(bucketLegacyMeta)
	legacyMetadataPresent := legacyMeta != nil && legacyMeta.Get([]byte(cliMetaKey)) != nil
	legacyNetwork, err := zone.LoadNetworkTx(tx)
	if err != nil {
		return report, false, err
	}
	legacyNetworkPresent := len(legacyNetwork.Zones) > 0

	if commonFound {
		if legacyMetadataPresent || legacyNetworkPresent {
			return report, false, errLegacyStateConflict
		}
		if _, found, err := loadLinuxRuntimeStateTx(tx); err != nil {
			return report, false, err
		} else if !found {
			return report, false, fmt.Errorf("%w: runtime bucket is missing", errLinuxRuntimeStateCorrupt)
		}
		return report, false, nil
	}
	if tx.Bucket(bucketLinuxRuntime) != nil {
		return report, false, errLegacyStateConflict
	}
	if !legacyMetadataPresent && !legacyNetworkPresent {
		return report, false, nil
	}
	if !legacyMetadataPresent || !legacyNetworkPresent {
		return report, false, fmt.Errorf("%w: incomplete legacy state", errLegacyStateConflict)
	}

	var meta stateMeta
	if err := json.Unmarshal(legacyMeta.Get([]byte(cliMetaKey)), &meta); err != nil {
		return report, false, fmt.Errorf("decode legacy %s: %w", cliMetaKey, err)
	}
	legacy := &stateFile{
		ManagedZone:       meta.ManagedZone,
		IdentityKeyPath:   meta.IdentityKeyPath,
		RootPrivateKey:    meta.RootPrivateKey,
		ZonePrivateKey:    meta.ZonePrivateKey,
		Network:           legacyNetwork,
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
	candidate, gossipReport, err := projectLegacyCommonState(legacy, trustedRoot)
	if err != nil {
		return report, false, err
	}
	report.Gossip = gossipReport
	if _, err := corestate.CommitBoltState(tx, candidate, corestate.ChangeSet{}); err != nil {
		return report, false, err
	}
	if _, err := saveLinuxRuntimeStateTx(tx, linuxRuntimeStateFromLegacy(legacy)); err != nil {
		return report, false, err
	}
	if _, err := zone.DeleteNetworkTx(tx); err != nil {
		return report, false, err
	}
	if err := legacyMeta.Delete([]byte(cliMetaKey)); err != nil {
		return report, false, err
	}
	return report, true, nil
}

func linuxRuntimeStateFromLegacy(state *stateFile) *linuxRuntimeState {
	if state == nil {
		return &linuxRuntimeState{}
	}
	return &linuxRuntimeState{
		IdentityKeyPath:   state.IdentityKeyPath,
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

func saveLinuxRuntimeStateTx(tx *bolt.Tx, state *linuxRuntimeState) (bool, error) {
	if tx == nil || !tx.Writable() {
		return false, errors.New("linux runtime save requires a writable bbolt transaction")
	}
	if state == nil {
		return false, errors.New("linux runtime state is nil")
	}
	bucket, err := tx.CreateBucketIfNotExists(bucketLinuxRuntime)
	if err != nil {
		return false, err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return false, err
	}
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], linuxRuntimeSchemaVersion)
	changed := false
	for _, item := range []struct{ key, value []byte }{
		{keyRuntimeSchema, version[:]},
		{keyRuntimePayload, payload},
	} {
		if bytes.Equal(bucket.Get(item.key), item.value) {
			continue
		}
		if err := bucket.Put(item.key, item.value); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

func loadLinuxRuntimeStateTx(tx *bolt.Tx) (*linuxRuntimeState, bool, error) {
	if tx == nil {
		return nil, false, errors.New("linux runtime load transaction is nil")
	}
	bucket := tx.Bucket(bucketLinuxRuntime)
	if bucket == nil {
		return nil, false, nil
	}
	version := bucket.Get(keyRuntimeSchema)
	if len(version) != 8 || binary.BigEndian.Uint64(version) != linuxRuntimeSchemaVersion {
		return nil, true, fmt.Errorf("%w: unsupported schema", errLinuxRuntimeStateCorrupt)
	}
	payload := bucket.Get(keyRuntimePayload)
	if payload == nil {
		return nil, true, fmt.Errorf("%w: payload is missing", errLinuxRuntimeStateCorrupt)
	}
	if bytes.Equal(bytes.TrimSpace(payload), []byte("null")) {
		return nil, true, fmt.Errorf("%w: payload is null", errLinuxRuntimeStateCorrupt)
	}
	var state linuxRuntimeState
	if err := json.Unmarshal(payload, &state); err != nil {
		return nil, true, fmt.Errorf("%w: %v", errLinuxRuntimeStateCorrupt, err)
	}
	return &state, true, nil
}
