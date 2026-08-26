package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	bolt "go.etcd.io/bbolt"
)

var errRuntimeStateSourceRevisionMismatch = errors.New("runtime state source verified revision does not match current state")

// linuxStateSnapshot is the complete persisted input needed to start the
// Linux runtime. Candidate owns the cross-platform trusted/checkpoint state;
// Runtime owns only Linux controller and configuration fields.
type linuxStateSnapshot struct {
	Candidate       *corestate.CommitCandidate
	Revision        corestate.VerifiedRevision
	Runtime         *linuxRuntimeState
	CommonReport    corestate.BoltLoadReport
	MigrationReport legacyStateMigrationReport
	Migrated        bool
}

// loadAndMigrateLinuxState composes the common and Linux bucket codecs through
// the process-wide BoltStore. It does not own or expose another DB handle.
func loadAndMigrateLinuxState(store *corestate.BoltStore, trustedRoot ed25519.PublicKey) (linuxStateSnapshot, bool, error) {
	var snapshot linuxStateSnapshot
	if store == nil {
		return snapshot, false, errors.New("bbolt state store is nil")
	}
	found := false
	err := store.Update(func(tx *bolt.Tx) (bool, error) {
		migrationReport, migrated, err := migrateLegacyRuntimeStateTx(tx, trustedRoot)
		if err != nil {
			return false, err
		}
		candidate, revision, commonReport, commonFound, err := corestate.LoadBoltState(tx)
		if err != nil {
			return false, err
		}
		if !commonFound {
			return migrated, nil
		}
		runtimeState, runtimeFound, err := loadLinuxRuntimeStateTx(tx)
		if err != nil {
			return false, err
		}
		if !runtimeFound {
			return false, fmt.Errorf("%w: runtime bucket is missing", errLinuxRuntimeStateCorrupt)
		}
		snapshot = linuxStateSnapshot{
			Candidate:       candidate,
			Revision:        revision,
			Runtime:         runtimeState,
			CommonReport:    commonReport,
			MigrationReport: migrationReport,
			Migrated:        migrated,
		}
		found = true
		return migrated, nil
	})
	return snapshot, found, err
}

// commitLinuxState atomically commits the common logical partitions and Linux
// runtime partition through the same BoltStore transaction.
func commitLinuxState(store *corestate.BoltStore, candidate *corestate.CommitCandidate, changes corestate.ChangeSet, runtimeState *linuxRuntimeState) error {
	if store == nil {
		return errors.New("bbolt state store is nil")
	}
	return store.Update(func(tx *bolt.Tx) (bool, error) {
		runtimeChanged, err := saveLinuxRuntimeStateTx(tx, runtimeState)
		if err != nil {
			return false, err
		}
		commonChanged, err := corestate.CommitBoltState(tx, candidate, changes)
		if err != nil {
			return false, err
		}
		return commonChanged || runtimeChanged, nil
	})
}

// commitLinuxRuntime persists a Linux-only completion without modifying the
// common candidate or VerifiedRevision. sourceRevision is the sole verified
// revision from which the controller planned its work.
func commitLinuxRuntime(store *corestate.BoltStore, sourceRevision corestate.VerifiedRevision, runtimeState *linuxRuntimeState) error {
	if store == nil {
		return errors.New("bbolt state store is nil")
	}
	return store.Update(func(tx *bolt.Tx) (bool, error) {
		_, currentRevision, _, found, err := corestate.LoadBoltState(tx)
		if err != nil {
			return false, err
		}
		if !found {
			return false, errors.New("common state is not initialized")
		}
		if sourceRevision != currentRevision {
			return false, fmt.Errorf("%w: completion=%d current=%d", errRuntimeStateSourceRevisionMismatch, sourceRevision, currentRevision)
		}
		return saveLinuxRuntimeStateTx(tx, runtimeState)
	})
}
