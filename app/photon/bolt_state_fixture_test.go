package main

import (
	"testing"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// seedPartitionedStateDB initializes an empty current-schema database and
// closes it so an offline command can reopen the file through production code.
func seedPartitionedStateDB(
	t *testing.T,
	path string,
	verified *corestate.VerifiedState,
	checkpoint *corestate.GossipCheckpoint,
	runtimeState *linuxRuntimeState,
) {
	t.Helper()
	store, err := corestate.OpenBoltStore(path, 0o600, daemonBoltLockTimeout)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	if err := initializeLinuxState(store, &corestate.CommitCandidate{
		Verified: verified,
		Gossip:   checkpoint,
	}, 0, runtimeState); err != nil {
		_ = store.Close()
		t.Fatalf("initializeLinuxState: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close BoltStore: %v", err)
	}
}
