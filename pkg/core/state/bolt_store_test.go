package state

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestBoltStoreNoopAndExternalLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "photon.db")
	store, err := OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	defer store.Close()
	if err := store.Update(func(*bolt.Tx) (bool, error) { return false, nil }); err != nil {
		t.Fatalf("no-op Update: %v", err)
	}
	_, err = OpenBoltStore(path, 0o600, 25*time.Millisecond)
	if !errors.Is(err, bolt.ErrTimeout) {
		t.Fatalf("second OpenBoltStore error = %v, want bbolt timeout", err)
	}
}

func TestBoltStoreCloseFailureIsReportedOnce(t *testing.T) {
	want := errors.New("injected close failure")
	fake := &closeFailureDB{err: want}
	store := &BoltStore{db: fake}
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

type closeFailureDB struct {
	err   error
	calls int
}

func (*closeFailureDB) View(func(*bolt.Tx) error) error   { return nil }
func (*closeFailureDB) Update(func(*bolt.Tx) error) error { return nil }
func (db *closeFailureDB) Close() error {
	db.calls++
	return db.err
}
