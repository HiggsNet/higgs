package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

var (
	ErrDelegationEpochStale    = errors.New("delegation authority epoch is stale")
	ErrDelegationEpochConflict = errors.New("delegation authority conflicts at the same epoch")
)

type LocalIntent interface {
	isLocalIntent()
}

type PutRecordIntent struct {
	Zone  zone.ZonePath
	Key   string
	Type  string
	Value []byte
}

func (PutRecordIntent) isLocalIntent() {}

type PutDelegationIntent struct {
	Parent    zone.ZonePath
	Authority *zone.ZoneAuthority
	ExpiresAt *time.Time
}

func (PutDelegationIntent) isLocalIntent() {}

type RevokeDelegationIntent struct {
	Parent zone.ZonePath
	Child  zone.ZonePath
	Reason string
}

func (RevokeDelegationIntent) isLocalIntent() {}

type LocalIntentResult struct {
	CommitResult
	Record     *zone.Record
	Delegation *zone.Delegation
	Revocation *zone.DelegationRevocation
}

// ApplyLocalIntent validates, signs and commits one authority-owned mutation.
// Private keys are ordinary persisted Store state under the administrator's
// filesystem/host security policy. Publication occurs only after persistence.
func (store *Store) ApplyLocalIntent(ctx context.Context, expected Revisions, intent LocalIntent, now time.Time) (LocalIntentResult, error) {
	var out LocalIntentResult
	if store == nil {
		return out, ErrVerifiedStoreClosed
	}
	if intent == nil {
		return out, errors.New("local intent is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	store.writeMu.Lock()
	defer store.writeMu.Unlock()

	store.mu.RLock()
	if store.closed {
		store.mu.RUnlock()
		return out, ErrVerifiedStoreClosed
	}
	baseRevisions := store.revisions
	candidate := cloneVerifiedState(store.state)
	gossipCandidate := cloneGossipCheckpoint(store.gossip)
	store.mu.RUnlock()
	if expected != baseRevisions {
		return out, ErrVerifiedRevisionStale
	}

	var changed zone.ZonePath
	var securityPriority bool
	var metadataChanged bool
	var err error
	switch typed := intent.(type) {
	case PutRecordIntent:
		out.Record, changed, err = applyPutRecordIntent(candidate, typed, now)
	case PutDelegationIntent:
		out.Delegation, changed, err = applyPutDelegationIntent(candidate, typed, now)
	case RevokeDelegationIntent:
		out.Revocation, changed, err = applyRevokeDelegationIntent(candidate, typed, now)
		if err == nil {
			securityPriority = true
			metadataChanged = cleanupRevokedPeerCheckpoint(gossipCandidate, typed.Child)
		}
	default:
		err = fmt.Errorf("unsupported local intent %T", intent)
	}
	if err != nil {
		return LocalIntentResult{}, err
	}
	if changed == "" {
		out.Changes.Revisions = baseRevisions
		return out, nil
	}
	nextRevisions := baseRevisions
	nextRevisions.Verified++
	if metadataChanged {
		nextRevisions.Checkpoint++
	}
	changes := ChangeSet{
		Revisions:               nextRevisions,
		ChangedZones:            []zone.ZonePath{changed},
		NetworkChanged:          true,
		GossipCheckpointChanged: metadataChanged,
		SecurityPriority:        securityPriority,
	}
	if store.repository != nil {
		if err := store.repository.Commit(ctx, baseRevisions, cloneCommitCandidate(candidate, gossipCandidate), changes); err != nil {
			return LocalIntentResult{}, err
		}
	}
	store.mu.Lock()
	store.state = candidate
	store.gossip = gossipCandidate
	store.revisions = nextRevisions
	store.mu.Unlock()
	out.Committed = true
	out.Changes = changes
	return cloneLocalIntentResult(out), nil
}

func applyPutRecordIntent(state *VerifiedState, intent PutRecordIntent, now time.Time) (*zone.Record, zone.ZonePath, error) {
	if !intent.Zone.Valid() {
		return nil, "", zone.ErrInvalidZonePath
	}
	if intent.Key == "" {
		return nil, "", zone.ErrInvalidFQKey
	}
	if state.Network.Zones[intent.Zone] == nil {
		return nil, "", fmt.Errorf("%w: %s", zone.ErrZoneNotFound, intent.Zone)
	}
	state.Network = zone.CloneNetworkStateForZone(state.Network, intent.Zone)
	state.Network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	zoneState := state.Network.Zones[intent.Zone]
	ensureZoneCollections(zoneState)
	current := zoneState.Records[intent.Key]
	record := &zone.Record{Zone: intent.Zone, Key: intent.Key, Type: intent.Type, Value: append([]byte(nil), intent.Value...), Version: 1, Timestamp: now.Unix()}
	if current != nil {
		record.Version = current.Version + 1
		record.PrevHash = photoncrypto.RecordHash(current)
	}
	privateKey, err := localSigningKey(state, intent.Zone)
	if err != nil {
		return nil, "", err
	}
	if err := photoncrypto.SignRecord(record, privateKey); err != nil {
		return nil, "", err
	}
	if err := state.Network.PutAt(record, now); err != nil {
		return nil, "", err
	}
	return cloneRecord(record), intent.Zone, nil
}

func applyPutDelegationIntent(state *VerifiedState, intent PutDelegationIntent, now time.Time) (*zone.Delegation, zone.ZonePath, error) {
	if !intent.Parent.Valid() || intent.Authority == nil || !intent.Authority.Zone.Valid() || intent.Authority.Zone.Parent() != intent.Parent {
		return nil, "", zone.ErrInvalidZonePath
	}
	parent := state.Network.Zones[intent.Parent]
	if parent == nil || parent.Authority == nil {
		return nil, "", fmt.Errorf("%w: %s", zone.ErrZoneNotFound, intent.Parent)
	}
	child := intent.Authority.Zone
	if existing := parent.Delegations[child]; existing != nil {
		nextHash := photoncrypto.AuthorityHash(intent.Authority)
		switch {
		case intent.Authority.Epoch < existing.AuthorityEpoch:
			return nil, "", ErrDelegationEpochStale
		case intent.Authority.Epoch == existing.AuthorityEpoch && !bytes.Equal(nextHash, existing.AuthorityHash):
			return nil, "", ErrDelegationEpochConflict
		case intent.Authority.Epoch == existing.AuthorityEpoch && bytes.Equal(nextHash, existing.AuthorityHash) && sameExpiry(existing.ExpiresAt, intent.ExpiresAt):
			return cloneDelegation(existing), "", nil
		}
	}
	state.Network = zone.CloneNetworkStateForZone(state.Network, intent.Parent)
	parent = state.Network.Zones[intent.Parent]
	ensureZoneCollections(parent)
	delegation := &zone.Delegation{ZoneName: child, Scope: zone.DelegationScopeDirectChild, Authority: *cloneAuthority(intent.Authority), ExpiresAt: cloneTime(intent.ExpiresAt)}
	privateKey, err := localSigningKey(state, intent.Parent)
	if err != nil {
		return nil, "", err
	}
	if err := photoncrypto.SignDelegation(delegation, intent.Parent, privateKey); err != nil {
		return nil, "", err
	}
	if err := photoncrypto.VerifyDelegation(delegation, parent.Authority, intent.Parent, now); err != nil {
		return nil, "", err
	}
	if revocation := parent.Revocations[child]; revocation != nil && (revocation.RevokedAuthorityEpoch >= delegation.AuthorityEpoch || bytes.Equal(revocation.RevokedAuthorityHash, delegation.AuthorityHash)) {
		return nil, "", fmt.Errorf("%w: %s", zone.ErrZoneRevoked, child)
	}
	parent.Delegations[child] = delegation
	return cloneDelegation(delegation), intent.Parent, nil
}

func applyRevokeDelegationIntent(state *VerifiedState, intent RevokeDelegationIntent, now time.Time) (*zone.DelegationRevocation, zone.ZonePath, error) {
	if !intent.Parent.Valid() || !intent.Child.Valid() || intent.Child.Parent() != intent.Parent {
		return nil, "", zone.ErrInvalidZonePath
	}
	parent := state.Network.Zones[intent.Parent]
	if parent == nil || parent.Authority == nil {
		return nil, "", fmt.Errorf("%w: %s", zone.ErrZoneNotFound, intent.Parent)
	}
	delegation := parent.Delegations[intent.Child]
	if delegation == nil {
		return nil, "", fmt.Errorf("delegation not found: %s", intent.Child)
	}
	state.Network = zone.CloneNetworkStateForZone(state.Network, intent.Parent)
	parent = state.Network.Zones[intent.Parent]
	ensureZoneCollections(parent)
	revocation := &zone.DelegationRevocation{
		ChildZone:             intent.Child,
		ParentZone:            intent.Parent,
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  append([]byte(nil), delegation.AuthorityHash...),
		Reason:                intent.Reason,
		RevokedAt:             now.Unix(),
	}
	privateKey, err := localSigningKey(state, intent.Parent)
	if err != nil {
		return nil, "", err
	}
	if err := photoncrypto.SignDelegationRevocation(revocation, intent.Parent, privateKey); err != nil {
		return nil, "", err
	}
	if err := photoncrypto.VerifyDelegationRevocation(revocation, parent.Authority, intent.Parent, now); err != nil {
		return nil, "", err
	}
	parent.Revocations[intent.Child] = revocation
	delete(parent.Delegations, intent.Child)
	return cloneRevocation(revocation), intent.Parent, nil
}

func sameExpiry(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

func localSigningKey(state *VerifiedState, path zone.ZonePath) (ed25519.PrivateKey, error) {
	if state == nil || state.Network == nil {
		return nil, errors.New("verified state is nil")
	}
	zoneState := state.Network.Zones[path]
	if zoneState == nil || zoneState.Authority == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	for _, privateKey := range []ed25519.PrivateKey{state.RootPrivateKey, state.IdentityPrivateKey} {
		if len(privateKey) == ed25519.PrivateKeySize && authorityHasPublicKey(zoneState.Authority, privateKey.Public().(ed25519.PublicKey)) {
			return append(ed25519.PrivateKey(nil), privateKey...), nil
		}
	}
	return nil, fmt.Errorf("no local signing key for zone %s", path)
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	out := *value
	return &out
}

func cloneLocalIntentResult(value LocalIntentResult) LocalIntentResult {
	value.Changes.ChangedZones = append([]zone.ZonePath(nil), value.Changes.ChangedZones...)
	value.Record = cloneRecord(value.Record)
	value.Delegation = cloneDelegation(value.Delegation)
	value.Revocation = cloneRevocation(value.Revocation)
	return value
}

func ensureZoneCollections(state *zone.ZoneState) {
	if state.Delegations == nil {
		state.Delegations = make(map[zone.ZonePath]*zone.Delegation)
	}
	if state.Revocations == nil {
		state.Revocations = make(map[zone.ZonePath]*zone.DelegationRevocation)
	}
	if state.Records == nil {
		state.Records = make(map[string]*zone.Record)
	}
	if state.RecordHistory == nil {
		state.RecordHistory = make(map[string][]*zone.Record)
	}
}

func cleanupRevokedPeerCheckpoint(state *GossipCheckpoint, revoked zone.ZonePath) bool {
	if state == nil || !revoked.Valid() {
		return false
	}
	changed := false
	for peerID := range state.Peers {
		path := zone.ZonePath(peerID)
		if path == revoked || zoneDescendsFrom(path, revoked) {
			delete(state.Peers, peerID)
			changed = true
		}
	}
	return changed
}

func zoneDescendsFrom(path, parent zone.ZonePath) bool {
	if !path.Valid() || !parent.Valid() || path == parent {
		return false
	}
	for current := path.Parent(); ; current = current.Parent() {
		if current == parent {
			return true
		}
		if current == zone.RootZone {
			return false
		}
	}
}
