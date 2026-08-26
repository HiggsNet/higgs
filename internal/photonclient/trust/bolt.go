// Package trust adapts persisted Photon state to the portable leaf-client
// StateSource contract. It deliberately reuses pkg/core/state ApplySnapshot
// instead of defining client- or platform-specific verification semantics.
package trust

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

// LoadBoltSnapshot reads an existing Photon bbolt store and rebuilds a
// detached network by passing every Zone through the same Snapshot and
// ApplySnapshot path used by the Linux daemon's gossip synchronization.
func LoadBoltSnapshot(path string, managed zone.ZonePath, trustedRoot ed25519.PublicKey, now time.Time, limits corestate.SyncLimits) (photonclient.StateSnapshot, error) {
	if !managed.Valid() || managed.IsRoot() {
		return photonclient.StateSnapshot{}, errors.New("managed zone must be a valid non-root Photon zone")
	}
	info, err := os.Stat(path)
	if err != nil {
		return photonclient.StateSnapshot{}, fmt.Errorf("stat Photon state %s: %w", path, err)
	}
	if info.IsDir() {
		return photonclient.StateSnapshot{}, fmt.Errorf("Photon state %s is a directory", path)
	}
	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		return photonclient.StateSnapshot{}, fmt.Errorf("open Photon state %s: %w", path, err)
	}
	network, loadErr := store.LoadNetwork()
	closeErr := store.Close()
	if loadErr != nil {
		return photonclient.StateSnapshot{}, fmt.Errorf("load Photon state %s: %w", path, loadErr)
	}
	if closeErr != nil {
		return photonclient.StateSnapshot{}, fmt.Errorf("close Photon state %s: %w", path, closeErr)
	}
	verified, err := verifyWithSharedState(network, managed, trustedRoot, now, limits)
	if err != nil {
		return photonclient.StateSnapshot{}, fmt.Errorf("verify Photon state %s: %w", path, err)
	}
	return photonclient.StateSnapshot{Revision: 1, ManagedZone: managed, Network: verified}, nil
}

func verifyWithSharedState(network *zone.NetworkState, managed zone.ZonePath, trustedRoot ed25519.PublicKey, now time.Time, limits corestate.SyncLimits) (*zone.NetworkState, error) {
	if network == nil || len(network.Zones) == 0 {
		return nil, errors.New("network state is empty")
	}
	if err := photoncrypto.VerifyPinnedRoot(network, trustedRoot); err != nil {
		return nil, err
	}
	if limits == (corestate.SyncLimits{}) {
		limits = corestate.DefaultSyncLimits()
	}
	paths := make([]zone.ZonePath, 0, len(network.Zones))
	for path := range network.Zones {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool {
		leftDepth := len(paths[i].Ancestors())
		rightDepth := len(paths[j].Ancestors())
		if leftDepth == rightDepth {
			return paths[i] < paths[j]
		}
		return leftDepth < rightDepth
	})

	verified := zone.NewNetworkState()
	for _, path := range paths {
		snapshot, err := corestate.Snapshot(network, path)
		if err != nil {
			return nil, fmt.Errorf("snapshot zone %s: %w", path, err)
		}
		next, _, err := corestate.ApplySnapshot(verified, snapshot, now, limits)
		if err != nil {
			return nil, fmt.Errorf("apply zone %s: %w", path, err)
		}
		verified = next
	}
	if verified.Zones[managed] == nil {
		return nil, fmt.Errorf("managed zone %s is absent from verified state", managed)
	}
	if err := photoncrypto.VerifyChain(verified, managed, now); err != nil {
		return nil, fmt.Errorf("verify managed zone %s: %w", managed, err)
	}
	return verified, nil
}

// StaticSource publishes one verified pre-provisioned snapshot. Network gossip
// will later replace this adapter without changing StateSource consumers.
type StaticSource struct {
	snapshot photonclient.StateSnapshot
	changes  chan uint64
	close    sync.Once
}

func NewStaticSource(snapshot photonclient.StateSnapshot) (*StaticSource, error) {
	if snapshot.Revision == 0 || snapshot.Network == nil || !snapshot.ManagedZone.Valid() || snapshot.ManagedZone.IsRoot() {
		return nil, errors.New("verified static state snapshot is incomplete")
	}
	snapshot.Network = zone.CloneNetworkState(snapshot.Network)
	snapshot.IdentityPrivateKey = append(ed25519.PrivateKey(nil), snapshot.IdentityPrivateKey...)
	return &StaticSource{snapshot: snapshot, changes: make(chan uint64)}, nil
}

func (s *StaticSource) Snapshot(ctx context.Context) (photonclient.StateSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return photonclient.StateSnapshot{}, err
	}
	copy := s.snapshot
	copy.Network = zone.CloneNetworkState(s.snapshot.Network)
	copy.IdentityPrivateKey = append(ed25519.PrivateKey(nil), s.snapshot.IdentityPrivateKey...)
	return copy, nil
}

func (s *StaticSource) Changes() <-chan uint64 {
	return s.changes
}

func (s *StaticSource) Close() error {
	s.close.Do(func() { close(s.changes) })
	return nil
}
