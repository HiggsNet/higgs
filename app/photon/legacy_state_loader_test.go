package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	bolt "go.etcd.io/bbolt"
)

// Older tests deliberately lock the detached constructor input to prove the
// daemon reads its typed owners. Keep that synchronization device in test code
// instead of forcing the production migration DTO to own a mutex.
var detachedAggregateTestLock sync.Mutex

func (*stateFile) Lock()   { detachedAggregateTestLock.Lock() }
func (*stateFile) Unlock() { detachedAggregateTestLock.Unlock() }

// LoadState remains test-only while older app tests are migrated to typed
// common/Linux owner fixtures. Production startup never reconstructs this
// aggregate view.
func (rt *Runtime) LoadState() (*stateFile, error) {
	return loadStateAtWithConfig(rt.StatePath, rt.Config)
}

func loadStateAtWithConfig(path string, config *appConfig) (*stateFile, error) {
	if config == nil {
		config = defaultAppConfig()
	}
	partitioned, found, err := loadPartitionedState(path, config)
	if err != nil || found {
		return partitioned, err
	}
	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		return nil, err
	}
	ns, err := store.LoadNetwork()
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	var meta stateMeta
	if err := store.LoadMetaJSON(cliMetaKey, &meta); err != nil {
		_ = store.Close()
		return nil, err
	}
	if ns == nil || len(ns.Zones) == 0 {
		if err := store.Close(); err != nil {
			return nil, err
		}
		if err := writeConfiguredPendingBootstrap(path, config); err != nil {
			return nil, err
		}
		return loadStateAtWithConfig(path, config)
	}
	if err := store.Close(); err != nil {
		return nil, err
	}
	state := &stateFile{
		ManagedZone: meta.ManagedZone, IdentityKeyPath: meta.IdentityKeyPath,
		RootPrivateKey: meta.RootPrivateKey, ZonePrivateKey: meta.ZonePrivateKey,
		Network: ns, SyncPeers: meta.SyncPeers, PeerCleanups: meta.PeerCleanups,
		IPsecTransportKey: meta.IPsecTransportKey, IPsecPortRecord: meta.IPsecPortRecord,
		LinkInstances: meta.LinkInstances, IPsecReconcile: meta.IPsecReconcile,
		RoutingReconcile: meta.RoutingReconcile, FirewallReconcile: meta.FirewallReconcile,
		EndpointACLs: meta.EndpointACLs, BirdInstances: meta.BirdInstances, Admission: meta.Admission,
	}
	normalizeState(state.Network)
	normalizeSyncPeers(state)
	if err := verifyConfiguredRootTrustAt(state.Network, config.TrustedRootPublicKey); err != nil {
		return nil, err
	}
	if err := applyConfiguredIdentityOverlay(state, config); err != nil {
		return nil, err
	}
	return state, nil
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
	if closeErr != nil || !found {
		return nil, found, closeErr
	}
	common, err := corestate.RestoreStore(snapshot.Candidate, snapshot.Revision, nil)
	if err != nil {
		return nil, false, err
	}
	state := composeLinuxStateView(common.ReadView(), snapshot.Runtime)
	if err := verifyConfiguredRootTrustAt(state.Network, config.TrustedRootPublicKey); err != nil {
		return nil, false, err
	}
	if err := applyConfiguredIdentityOverlay(state, config); err != nil {
		return nil, false, err
	}
	return state, true, nil
}

func verifyConfiguredRootTrustAt(ns *zone.NetworkState, trustRoot ed25519.PublicKey) error {
	if len(trustRoot) == 0 {
		return nil
	}
	return photoncrypto.VerifyPinnedRoot(ns, trustRoot)
}

func applyConfiguredIdentityOverlay(state *stateFile, config *appConfig) error {
	if state == nil || config == nil || (config.ManagedZone == "" && config.Identity.KeyPath == "") {
		return nil
	}
	if state.ManagedZone == "" {
		return errors.New("configured identity requires initialized ManagedZone; use a new data_dir/state_path to create this node")
	}
	if config.ManagedZone != "" && state.ManagedZone != config.ManagedZone {
		return fmt.Errorf("managed_zone %s does not match DB ManagedZone %s; identity is immutable, use a new data_dir/state_path to create a different node", config.ManagedZone, state.ManagedZone)
	}
	if config.Identity.KeyPath == "" {
		return nil
	}
	key, keyPath, err := configuredIdentityKey(config)
	if err != nil {
		return err
	}
	if state.IdentityKeyPath != "" && state.IdentityKeyPath != keyPath {
		return fmt.Errorf("identity.key_path %s does not match DB identity key path %s; identity is immutable, use a new data_dir/state_path to create a different node", keyPath, state.IdentityKeyPath)
	}
	if len(state.ZonePrivateKey) == ed25519.PrivateKeySize {
		if !equalPublicKey(state.ZonePrivateKey.Public().(ed25519.PublicKey), key.PublicKey) {
			return errors.New("identity.key_path public key does not match DB ZonePrivateKey; identity is immutable, use a new data_dir/state_path to create a different node")
		}
	} else if len(state.ZonePrivateKey) != 0 {
		return errors.New("DB ZonePrivateKey is invalid")
	}
	if state.Network != nil {
		if zs := state.Network.Zones[state.ManagedZone]; zs != nil && zs.Authority != nil && !authorityHasKey(zs.Authority, key.PublicKey) {
			return fmt.Errorf("identity.key_path public key does not match ManagedZone authority for %s; identity is immutable, use a new data_dir/state_path to create a different node", state.ManagedZone)
		}
	}
	state.IdentityKeyPath = keyPath
	state.ZonePrivateKey = append(ed25519.PrivateKey(nil), key.PrivateKey...)
	return nil
}

func normalizeSyncPeers(state *stateFile) {
	if state.SyncPeers == nil {
		state.SyncPeers = make(map[string]syncPeerState)
	}
	if state.PeerCleanups == nil {
		state.PeerCleanups = make(map[string]peerLifecycleCleanupState)
	}
}
