package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

type memoryVerifiedRepository struct {
	mu      sync.Mutex
	commits int
	state   *CommitCandidate
	changes ChangeSet
	err     error
}

func (repository *memoryVerifiedRepository) Commit(_ context.Context, state *CommitCandidate, changes ChangeSet) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.err != nil {
		return repository.err
	}
	repository.commits++
	repository.state = cloneCommitCandidate(state.Verified, state.Gossip)
	repository.changes = changes
	return nil
}

func TestStoreApplyRemoteBatchRetainsSuccessRejectSuccess(t *testing.T) {
	now := time.Unix(1000, 0)
	initial, privateKey := testNetwork(t)
	initial.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	source := cloneNetworkState(initial)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)

	v1 := signedRecord(t, privateKey, "catofes.", "identity", []byte("v1"), 1, nil, now.Unix())
	if err := source.PutAt(v1, now); err != nil {
		t.Fatalf("PutAt(v1): %v", err)
	}
	snapshotV1, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(v1): %v", err)
	}
	v2 := signedRecord(t, privateKey, "catofes.", "identity", []byte("v2"), 2, photoncrypto.RecordHash(v1), now.Unix()+1)
	if err := source.PutAt(v2, now.Add(time.Second)); err != nil {
		t.Fatalf("PutAt(v2): %v", err)
	}
	snapshotV2, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(v2): %v", err)
	}
	bad := &ZoneSnapshot{Zone: "evil.catofes.", Authority: snapshotV1.Authority}

	repository := &memoryVerifiedRepository{}
	store := NewStore(&VerifiedState{ManagedZone: "node-a.catofes.", Network: initial}, repository)
	result, err := store.ApplyRemoteBatch(context.Background(), "peer-a", []RemoteSnapshot{
		{Snapshot: snapshotV1, ExpectedRoot: ZoneRoot(ZoneStateFromSnapshot(snapshotV1))},
		{Snapshot: bad, ExpectedRoot: []byte("advertised-root")},
		{Snapshot: snapshotV2, ExpectedRoot: ZoneRoot(ZoneStateFromSnapshot(snapshotV2))},
	}, now)
	if err != nil {
		t.Fatalf("ApplyRemoteBatch: %v", err)
	}
	if !result.Committed || !result.Changes.NetworkChanged || !result.Changes.GossipCheckpointChanged {
		t.Fatalf("commit result = %+v, want network and metadata commit", result.CommitResult)
	}
	if len(result.Outcomes) != 3 || result.Outcomes[0].Err != nil || !errors.Is(result.Outcomes[1].Err, ErrSnapshotRootMismatch) || result.Outcomes[2].Err != nil {
		t.Fatalf("outcomes = %#v, want success/reject/success", result.Outcomes)
	}
	view := store.ReadView()
	if got := string(view.State.Network.Zones["catofes."].Records["identity"].Value); got != "v2" {
		t.Fatalf("identity = %q, want v2", got)
	}
	rejected := view.Gossip.Peers["peer-a"].RejectedObjects["evil.catofes."]
	if rejected.Reason != "root_mismatch" || !bytes.Equal(rejected.RootHash, []byte("advertised-root")) {
		t.Fatalf("rejected metadata = %#v", rejected)
	}
	if view.Revision != 1 {
		t.Fatalf("verified revision = %d, want 1", view.Revision)
	}
	if repository.commits != 1 {
		t.Fatalf("repository commits = %d, want 1", repository.commits)
	}
}

func TestStoreApplyRemoteBatchRejectsRootAuthorityReplacement(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _, identityPrivate, _ := managedAuthorityFixture(t, true)
	trustedRoot := append(ed25519.PublicKey(nil), network.Zones[zone.RootZone].Authority.Keys[0].Key...)
	source := cloneNetworkState(network)
	otherPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(other root): %v", err)
	}
	source.Zones[zone.RootZone].Authority = &zone.ZoneAuthority{
		Zone: zone.RootZone, Epoch: 2, Threshold: 1,
		Keys: []zone.AuthorizedKey{{Key: otherPublic}},
	}
	snapshot, err := Snapshot(source, zone.RootZone)
	if err != nil {
		t.Fatalf("Snapshot(root): %v", err)
	}
	store := NewStore(&VerifiedState{
		ManagedZone:          "node-a.catofes.",
		Network:              network,
		TrustedRootPublicKey: trustedRoot,
		IdentityPrivateKey:   identityPrivate,
	}, nil)
	result, err := store.ApplyRemoteBatch(context.Background(), "peer-a", []RemoteSnapshot{{
		Snapshot: snapshot, ExpectedRoot: ZoneRoot(ZoneStateFromSnapshot(snapshot)),
	}}, now)
	if err != nil {
		t.Fatalf("ApplyRemoteBatch: %v", err)
	}
	if len(result.Outcomes) != 1 || !errors.Is(result.Outcomes[0].Err, ErrTrustedRootAuthorityChange) {
		t.Fatalf("outcomes = %#v, want trusted-root authority rejection", result.Outcomes)
	}
	view := store.ReadView()
	if view.Revision != 0 || !bytes.Equal(view.State.Network.Zones[zone.RootZone].Authority.Keys[0].Key, trustedRoot) {
		t.Fatalf("root replacement changed verified state at revision %d", view.Revision)
	}
}

func TestStoreRepositoryFailureLeavesStateAndRevisionUnchanged(t *testing.T) {
	now := time.Unix(1000, 0)
	initial, privateKey := testNetwork(t)
	source := cloneNetworkState(initial)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	record := signedRecord(t, privateKey, "catofes.", "identity", []byte("new"), 1, nil, now.Unix())
	if err := source.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	wantErr := errors.New("disk unavailable")
	store := NewStore(&VerifiedState{Network: initial}, &memoryVerifiedRepository{err: wantErr})
	_, err = store.ApplyRemoteBatch(context.Background(), "peer-a", []RemoteSnapshot{{Snapshot: snapshot}}, now)
	if !errors.Is(err, wantErr) {
		t.Fatalf("ApplyRemoteBatch error = %v, want %v", err, wantErr)
	}
	view := store.ReadView()
	if view.Revision != 0 {
		t.Fatalf("verified revision = %d, want zero", view.Revision)
	}
	if view.State.Network.Zones["catofes."].Records["identity"] != nil {
		t.Fatal("repository failure published candidate")
	}
}

func TestStoreReadViewIsDetached(t *testing.T) {
	now := time.Unix(1000, 0)
	initial, privateKey := testNetwork(t)
	source := cloneNetworkState(initial)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	record := signedRecord(t, privateKey, "catofes.", "identity", []byte("committed"), 1, nil, now.Unix())
	if err := source.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	store := NewStore(&VerifiedState{Network: initial, TrustedRootPublicKey: ed25519.PublicKey("root")}, nil)
	if _, err := store.ApplyRemoteBatch(context.Background(), "peer-a", []RemoteSnapshot{{Snapshot: snapshot}}, now); err != nil {
		t.Fatalf("ApplyRemoteBatch: %v", err)
	}
	view := store.ReadView()
	view.State.TrustedRootPublicKey[0] = 'X'
	view.State.Network.Zones["catofes."].Records["identity"].Value[0] = 'X'
	fresh := store.ReadView()
	if string(fresh.State.TrustedRootPublicKey) != "root" || string(fresh.State.Network.Zones["catofes."].Records["identity"].Value) != "committed" {
		t.Fatal("mutating read view changed committed state")
	}
}

func TestStoreDoesNotRetainInitialState(t *testing.T) {
	initial, _ := testNetwork(t)
	rootKey := ed25519.PublicKey("root")
	input := &VerifiedState{Network: initial, TrustedRootPublicKey: rootKey}
	store := NewStore(input, nil)

	rootKey[0] = 'X'
	input.TrustedRootPublicKey[1] = 'Y'
	delete(initial.Zones, "catofes.")
	view := store.ReadView()
	if string(view.State.TrustedRootPublicKey) != "root" || view.State.Network.Zones["catofes."] == nil {
		t.Fatal("store retained mutable initial state")
	}
}

func TestStoreConcurrentReadersSeeWholeRevision(t *testing.T) {
	now := time.Unix(1000, 0)
	initial, privateKey := testNetwork(t)
	source := cloneNetworkState(initial)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	record := signedRecord(t, privateKey, "catofes.", "identity", []byte("committed"), 1, nil, now.Unix())
	if err := source.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	store := NewStore(&VerifiedState{Network: initial}, nil)

	var readers sync.WaitGroup
	for range 8 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 100 {
				view := store.ReadView()
				record := view.State.Network.Zones[zone.ZonePath("catofes.")].Records["identity"]
				if view.Revision == 0 && record != nil {
					t.Errorf("reader saw new state at old revision")
					return
				}
				if view.Revision == 1 && (record == nil || string(record.Value) != "committed") {
					t.Errorf("reader saw incomplete state at new revision")
					return
				}
			}
		}()
	}
	if _, err := store.ApplyRemoteBatch(context.Background(), "peer-a", []RemoteSnapshot{{Snapshot: snapshot}}, now); err != nil {
		t.Fatalf("ApplyRemoteBatch: %v", err)
	}
	readers.Wait()
}

func TestStoreUpdatePeerCheckpointIsTypedDetachedAndCheckpointOnly(t *testing.T) {
	initial, _ := testNetwork(t)
	repository := &memoryVerifiedRepository{}
	store := NewStore(&VerifiedState{Network: initial}, repository)
	root := []byte("rejected-root")
	grace := []ObservedGraceEndpoint{{Endpoint: "192.0.2.2:4242", UntilUnix: 200}}
	result, err := store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{
		LastSyncUnix:       PatchField[int64]{Set: true, Value: 100},
		BackoffUntilUnix:   PatchField[int64]{Set: true, Value: 150},
		FailureCount:       PatchField[int]{Set: true, Value: 2},
		DiscoveredEndpoint: PatchField[string]{Set: true, Value: "192.0.2.1:4242"},
		ObservedGrace:      PatchField[[]ObservedGraceEndpoint]{Set: true, Value: grace},
		Reject: map[zone.ZonePath]RejectedObject{
			"bad.catofes.": {RootHash: root, Reason: "untrusted_zone", UpdatedUnix: 100},
		},
	})
	if err != nil {
		t.Fatalf("UpdatePeerCheckpoint: %v", err)
	}
	if !result.Committed || result.Changes.NetworkChanged || !result.Changes.GossipCheckpointChanged {
		t.Fatalf("commit result = %+v", result)
	}
	if result.Changes.VerifiedRevision != 0 {
		t.Fatalf("checkpoint changed verified revision to %d", result.Changes.VerifiedRevision)
	}
	root[0] = 'X'
	grace[0].Endpoint = "mutated"
	view := store.ReadView()
	peer := view.Gossip.Peers["peer-a"]
	if peer.LastSyncUnix != 100 || peer.BackoffUntilUnix != 150 || peer.FailureCount != 2 || peer.ObservedGraceEndpoints[0].Endpoint != "192.0.2.2:4242" {
		t.Fatalf("peer metadata = %+v", peer)
	}
	if string(peer.RejectedObjects["bad.catofes."].RootHash) != "rejected-root" {
		t.Fatal("metadata patch retained rejected root input")
	}
	if repository.commits != 1 || repository.changes.NetworkChanged {
		t.Fatalf("repository commit = %d/%+v", repository.commits, repository.changes)
	}

	clearResult, err := store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{
		ClearRejected: []zone.ZonePath{"bad.catofes."},
	})
	if err != nil || !clearResult.Committed {
		t.Fatalf("clear rejected result/error = %+v/%v", clearResult, err)
	}
	if len(store.ReadView().Gossip.Peers["peer-a"].RejectedObjects) != 0 {
		t.Fatal("clear rejected patch did not remove entry")
	}
}

func TestStoreUpdatePeerCheckpointNoopAndRepositoryFailure(t *testing.T) {
	repository := &memoryVerifiedRepository{}
	store := NewStore(nil, repository)
	result, err := store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{})
	if err != nil || result.Committed || repository.commits != 0 {
		t.Fatalf("empty patch result/error/commits = %+v/%v/%d", result, err, repository.commits)
	}

	wantErr := errors.New("metadata persistence failed")
	repository.err = wantErr
	_, err = store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{
		LastAttemptUnix: PatchField[int64]{Set: true, Value: 100},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("UpdatePeerCheckpoint error = %v, want %v", err, wantErr)
	}
	view := store.ReadView()
	if view.Revision != 0 || len(view.Gossip.Peers) != 0 {
		t.Fatalf("repository failure published metadata: %+v", view)
	}
}
