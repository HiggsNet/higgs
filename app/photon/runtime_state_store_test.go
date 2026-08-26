package main

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	bolt "go.etcd.io/bbolt"
)

func TestLinuxRuntimeStateStoreMigratesAndReloadsAggregate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	legacy, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyRuntimeState(t, path, legacy)

	store, err := openLinuxRuntimeStateStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("openLinuxRuntimeStateStore: %v", err)
	}
	snapshot, found, err := store.LoadAndMigrate(trustedRoot)
	if err != nil {
		t.Fatalf("LoadAndMigrate: %v", err)
	}
	if !found || !snapshot.Migrated || snapshot.Candidate == nil || snapshot.Runtime == nil {
		t.Fatalf("migration snapshot = found=%v %+v", found, snapshot)
	}
	if snapshot.Runtime.IdentityKeyPath != legacy.IdentityKeyPath || snapshot.MigrationReport.Gossip.PeersMigrated != 1 {
		t.Fatalf("migration snapshot runtime/report = %+v/%+v", snapshot.Runtime, snapshot.MigrationReport)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := openLinuxRuntimeStateStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("reopenLinuxRuntimeStateStore: %v", err)
	}
	defer reopened.Close()
	reloaded, found, err := reopened.LoadAndMigrate(trustedRoot)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !found || reloaded.Migrated || !reflect.DeepEqual(reloaded.Candidate, snapshot.Candidate) || !reflect.DeepEqual(reloaded.Runtime, snapshot.Runtime) {
		t.Fatalf("reloaded snapshot = found=%v %+v", found, reloaded)
	}
}

func TestLinuxRuntimeStateStoreAggregateRollbackAndNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	legacy, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyRuntimeState(t, path, legacy)
	store, err := openLinuxRuntimeStateStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("openLinuxRuntimeStateStore: %v", err)
	}
	defer store.Close()
	snapshot, _, err := store.LoadAndMigrate(trustedRoot)
	if err != nil {
		t.Fatalf("LoadAndMigrate: %v", err)
	}

	before := boltTxID(t, path, store)
	if err := store.CommitAggregate(snapshot.Candidate, corestate.ChangeSet{VerifiedRevision: snapshot.Revision}, snapshot.Runtime); err != nil {
		t.Fatalf("no-op CommitAggregate: %v", err)
	}
	if after := boltTxID(t, path, store); after != before {
		t.Fatalf("no-op advanced bbolt txid from %d to %d", before, after)
	}

	badRuntime := *snapshot.Runtime
	badRuntime.IdentityKeyPath = "/changed-before-rollback"
	badCandidate := *snapshot.Candidate
	badVerified := *snapshot.Candidate.Verified
	badVerified.TrustedRootPublicKey = append([]byte(nil), badVerified.TrustedRootPublicKey...)
	badVerified.TrustedRootPublicKey[0] ^= 0xff
	badCandidate.Verified = &badVerified
	if err := store.CommitAggregate(&badCandidate, corestate.ChangeSet{VerifiedRevision: snapshot.Revision}, &badRuntime); !errors.Is(err, corestate.ErrInvalidStateRoot) {
		t.Fatalf("CommitAggregate error = %v, want ErrInvalidStateRoot", err)
	}
	reloaded, found, err := store.LoadAndMigrate(trustedRoot)
	if err != nil || !found {
		t.Fatalf("reload after rollback = found=%v err=%v", found, err)
	}
	if reloaded.Runtime.IdentityKeyPath != snapshot.Runtime.IdentityKeyPath {
		t.Fatalf("failed common commit retained platform write: %q", reloaded.Runtime.IdentityKeyPath)
	}
}

func TestLinuxRuntimeStateStoreRepositoryUsesOwnedHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	legacy, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyRuntimeState(t, path, legacy)
	store, err := openLinuxRuntimeStateStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("openLinuxRuntimeStateStore: %v", err)
	}
	defer store.Close()
	snapshot, _, err := store.LoadAndMigrate(trustedRoot)
	if err != nil {
		t.Fatalf("LoadAndMigrate: %v", err)
	}
	if err := store.Commit(context.Background(), snapshot.Candidate, corestate.ChangeSet{VerifiedRevision: snapshot.Revision}); err != nil {
		t.Fatalf("Repository.Commit no-op: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Commit(canceled, snapshot.Candidate, corestate.ChangeSet{VerifiedRevision: snapshot.Revision}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Commit error = %v", err)
	}
}

func TestLinuxRuntimeStateStoreRejectsNilPlatformState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	legacy, trustedRoot := legacyRuntimeMigrationFixture(t)
	seedLegacyRuntimeState(t, path, legacy)
	store, err := openLinuxRuntimeStateStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("openLinuxRuntimeStateStore: %v", err)
	}
	defer store.Close()
	snapshot, _, err := store.LoadAndMigrate(trustedRoot)
	if err != nil {
		t.Fatalf("LoadAndMigrate: %v", err)
	}
	if err := store.CommitAggregate(snapshot.Candidate, corestate.ChangeSet{VerifiedRevision: snapshot.Revision}, nil); err == nil {
		t.Fatal("nil Linux runtime state unexpectedly committed")
	}
}

func TestLinuxRuntimeStateStoreRejectsExternalHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	store, err := openLinuxRuntimeStateStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("openLinuxRuntimeStateStore: %v", err)
	}
	defer store.Close()
	started := time.Now()
	_, err = openLinuxRuntimeStateStore(path, 0o600, 25*time.Millisecond)
	if !errors.Is(err, bolt.ErrTimeout) {
		t.Fatalf("second open error = %v, want bbolt timeout", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("external lock conflict did not respect timeout")
	}
}

func TestLinuxRuntimeStateStoreCloseFailureIsReportedOnce(t *testing.T) {
	want := errors.New("injected close failure")
	fake := &closeFailureBoltDB{err: want}
	store := &linuxRuntimeStateStore{db: fake}
	if err := store.Close(); !errors.Is(err, want) {
		t.Fatalf("Close error = %v, want %v", err, want)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close error = %v", err)
	}
	if fake.calls != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", fake.calls)
	}
}

func boltTxID(t *testing.T, _ string, store *linuxRuntimeStateStore) uint64 {
	t.Helper()
	var id uint64
	if err := store.db.View(func(tx *bolt.Tx) error {
		id = uint64(tx.ID())
		return nil
	}); err != nil {
		t.Fatalf("read txid: %v", err)
	}
	return id
}

type closeFailureBoltDB struct {
	err   error
	calls int
}

func (*closeFailureBoltDB) View(func(*bolt.Tx) error) error   { return nil }
func (*closeFailureBoltDB) Update(func(*bolt.Tx) error) error { return nil }
func (db *closeFailureBoltDB) Close() error {
	db.calls++
	return db.err
}
