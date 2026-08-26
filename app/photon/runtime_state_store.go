package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	bolt "go.etcd.io/bbolt"
)

var errRuntimeStateStoreNoChanges = errors.New("runtime state store transaction has no changes")

type runtimeStateBoltDB interface {
	View(func(*bolt.Tx) error) error
	Update(func(*bolt.Tx) error) error
	Close() error
}

// linuxRuntimeStateSnapshot is the complete persisted input needed to start a
// Linux HostRuntime. Candidate owns the cross-platform trusted/checkpoint
// state; Runtime owns only Linux controller and configuration state.
type linuxRuntimeStateSnapshot struct {
	Candidate       *corestate.CommitCandidate
	Revision        corestate.VerifiedRevision
	Runtime         *linuxRuntimeState
	CommonReport    corestate.BoltLoadReport
	MigrationReport legacyStateMigrationReport
	Migrated        bool
}

// linuxRuntimeStateStore owns the process-wide bbolt handle used by the future
// Linux HostRuntime cutover. It deliberately does not expose the handle: all
// common and platform writes must be composed through this owner.
//
// The current daemon loader/writer does not use this type yet. Switching those
// call sites is one atomic E-stage change so legacy and common writers never
// coexist online.
type linuxRuntimeStateStore struct {
	mu     sync.Mutex
	db     runtimeStateBoltDB
	closed bool
}

var _ corestate.Repository = (*linuxRuntimeStateStore)(nil)

func openLinuxRuntimeStateStore(path string, mode os.FileMode, lockTimeout time.Duration) (*linuxRuntimeStateStore, error) {
	if path == "" {
		return nil, errors.New("runtime state path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, mode, &bolt.Options{Timeout: lockTimeout})
	if err != nil {
		return nil, fmt.Errorf("open runtime state %s: %w", path, err)
	}
	return &linuxRuntimeStateStore{db: db}, nil
}

// LoadAndMigrate reads the new aggregate, migrating a complete legacy Linux
// state in the same transaction when necessary. A migration or decode failure
// rolls the whole transaction back and leaves the store reusable for retry.
func (store *linuxRuntimeStateStore) LoadAndMigrate(trustedRoot ed25519.PublicKey) (linuxRuntimeStateSnapshot, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var snapshot linuxRuntimeStateSnapshot
	if store.closed || store.db == nil {
		return snapshot, false, errors.New("runtime state store is closed")
	}
	found := false
	err := store.db.Update(func(tx *bolt.Tx) error {
		migrationReport, migrated, err := migrateLegacyRuntimeStateTx(tx, trustedRoot)
		if err != nil {
			return err
		}
		candidate, revision, commonReport, commonFound, err := corestate.LoadBoltState(tx)
		if err != nil {
			return err
		}
		if !commonFound {
			return nil
		}
		runtimeState, runtimeFound, err := loadLinuxRuntimeStateTx(tx)
		if err != nil {
			return err
		}
		if !runtimeFound {
			return fmt.Errorf("%w: runtime bucket is missing", errLinuxRuntimeStateCorrupt)
		}
		snapshot = linuxRuntimeStateSnapshot{
			Candidate:       candidate,
			Revision:        revision,
			Runtime:         runtimeState,
			CommonReport:    commonReport,
			MigrationReport: migrationReport,
			Migrated:        migrated,
		}
		found = true
		return nil
	})
	return snapshot, found, err
}

// CommitAggregate atomically commits the common root and Linux runtime root.
// A byte-identical aggregate is rolled back as a no-op, avoiding a bbolt commit
// and disk write while preserving the same successful API result.
func (store *linuxRuntimeStateStore) CommitAggregate(candidate *corestate.CommitCandidate, changes corestate.ChangeSet, runtimeState *linuxRuntimeState) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed || store.db == nil {
		return errors.New("runtime state store is closed")
	}
	err := store.db.Update(func(tx *bolt.Tx) error {
		runtimeChanged, err := saveLinuxRuntimeStateTx(tx, runtimeState)
		if err != nil {
			return err
		}
		commonChanged, err := corestate.CommitBoltState(tx, candidate, changes)
		if err != nil {
			return err
		}
		if !commonChanged && !runtimeChanged {
			return errRuntimeStateStoreNoChanges
		}
		return nil
	})
	if errors.Is(err, errRuntimeStateStoreNoChanges) {
		return nil
	}
	return err
}

// Commit implements state.Repository. It persists only the common candidate,
// but still uses this store's sole handle and serialized writer. Platform
// checkpoint writes use CommitAggregate when they must share the transaction.
func (store *linuxRuntimeStateStore) Commit(ctx context.Context, candidate *corestate.CommitCandidate, changes corestate.ChangeSet) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if store.closed || store.db == nil {
		return errors.New("runtime state store is closed")
	}
	err := store.db.Update(func(tx *bolt.Tx) error {
		changed, err := corestate.CommitBoltState(tx, candidate, changes)
		if err != nil {
			return err
		}
		if !changed {
			return errRuntimeStateStoreNoChanges
		}
		return nil
	})
	if errors.Is(err, errRuntimeStateStoreNoChanges) {
		return nil
	}
	return err
}

func (store *linuxRuntimeStateStore) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	if store.db == nil {
		return nil
	}
	return store.db.Close()
}
