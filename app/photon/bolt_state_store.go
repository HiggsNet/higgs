package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	bolt "go.etcd.io/bbolt"
)

const daemonBoltLockTimeout = time.Second

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

// linuxStartupState is the final ownership split used by the Linux process:
// Common owns verified facts and gossip restart hints, while Runtime contains
// only Linux controller/configuration state. Both persist through the same
// process-wide BoltStore handle.
type linuxStartupState struct {
	Common          *corestate.Store
	Runtime         *linuxRuntimeState
	CommonReport    corestate.BoltLoadReport
	MigrationReport legacyStateMigrationReport
	Migrated        bool
}

func openLinuxDaemonState(rt *Runtime) (*corestate.BoltStore, linuxStartupState, error) {
	var startup linuxStartupState
	if rt == nil || rt.Config == nil || rt.StatePath == "" {
		return nil, startup, errors.New("daemon runtime state path is not configured")
	}
	store, err := corestate.OpenBoltStore(rt.StatePath, 0o600, daemonBoltLockTimeout)
	if err != nil {
		return nil, startup, err
	}
	startup, found, err := loadAndRestoreLinuxState(store, rt.Config.TrustedRootPublicKey)
	if err != nil {
		_ = store.Close()
		return nil, linuxStartupState{}, err
	}
	if found {
		return store, startup, nil
	}
	// Only an uninitialized database may enter the legacy bootstrap path. Once
	// common state exists, every reopen above is independent of the old Network
	// and meta representation.
	if err := store.Close(); err != nil {
		return nil, linuxStartupState{}, err
	}
	if _, err := rt.LoadState(); err != nil {
		return nil, linuxStartupState{}, err
	}
	store, err = corestate.OpenBoltStore(rt.StatePath, 0o600, daemonBoltLockTimeout)
	if err != nil {
		return nil, linuxStartupState{}, err
	}
	startup, found, err = loadAndRestoreLinuxState(store, rt.Config.TrustedRootPublicKey)
	if err != nil || !found {
		_ = store.Close()
		if err != nil {
			return nil, linuxStartupState{}, err
		}
		return nil, linuxStartupState{}, errors.New("daemon state is not initialized")
	}
	return store, startup, nil
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
		loaded, commonFound, err := loadLinuxStateTx(tx)
		if err != nil {
			return false, err
		}
		if !commonFound {
			return migrated, nil
		}
		snapshot = loaded
		snapshot.MigrationReport = migrationReport
		snapshot.Migrated = migrated
		found = true
		return migrated, nil
	})
	return snapshot, found, err
}

func loadLinuxStateTx(tx *bolt.Tx) (linuxStateSnapshot, bool, error) {
	candidate, revision, commonReport, found, err := corestate.LoadBoltState(tx)
	if err != nil || !found {
		return linuxStateSnapshot{}, found, err
	}
	runtimeState, runtimeFound, err := loadLinuxRuntimeStateTx(tx)
	if err != nil {
		return linuxStateSnapshot{}, false, err
	}
	if !runtimeFound {
		return linuxStateSnapshot{}, false, fmt.Errorf("%w: runtime bucket is missing", errLinuxRuntimeStateCorrupt)
	}
	return linuxStateSnapshot{
		Candidate:    candidate,
		Revision:     revision,
		Runtime:      runtimeState,
		CommonReport: commonReport,
	}, true, nil
}

// loadAndRestoreLinuxState performs the complete persistent startup boundary:
// it upgrades a legacy database when necessary, loads both logical partitions
// through one BoltStore transaction, and restores the common in-memory Store
// with the persisted verified revision. The returned Store commits directly
// through the same BoltStore owner.
//
// The online daemon uses this as its sole startup path; verified, checkpoint
// and Linux runtime writes all return through the same BoltStore owner.
func loadAndRestoreLinuxState(store *corestate.BoltStore, trustedRoot ed25519.PublicKey) (linuxStartupState, bool, error) {
	var startup linuxStartupState
	snapshot, found, err := loadAndMigrateLinuxState(store, trustedRoot)
	if err != nil || !found {
		return startup, found, err
	}
	common, err := corestate.RestoreStore(snapshot.Candidate, snapshot.Revision, store.CommitCommon)
	if err != nil {
		return startup, false, err
	}
	startup = linuxStartupState{
		Common:          common,
		Runtime:         snapshot.Runtime,
		CommonReport:    snapshot.CommonReport,
		MigrationReport: snapshot.MigrationReport,
		Migrated:        snapshot.Migrated,
	}
	return startup, true, nil
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
