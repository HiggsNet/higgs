package main

import (
	"context"
	"errors"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func newComposedDaemonStateStoreTestFixture(t *testing.T, commit corestate.CommitFunc) (*DaemonStateStore, zone.ZonePath) {
	t.Helper()
	rt, managed := buildIPAMTestRuntime(t)
	legacy, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	candidate, _, err := projectLegacyCommonState(legacy, rt.Config.TrustedRootPublicKey)
	if err != nil {
		t.Fatalf("projectLegacyCommonState: %v", err)
	}
	common := corestate.NewStoreWithCheckpoint(candidate.Verified, candidate.Gossip, commit)
	store, err := NewComposedDaemonStateStore(common, &linuxRuntimeState{
		IdentityKeyPath: legacy.IdentityKeyPath,
		EndpointACLs:    map[string]endpointACL{"admin": {Name: "admin"}},
	})
	if err != nil {
		t.Fatalf("NewComposedDaemonStateStore: %v", err)
	}
	return store, zone.ZonePath(managed)
}

func TestComposedDaemonStateStoreAppliesCommonIntentAndRefreshesReadView(t *testing.T) {
	store, managed := newComposedDaemonStateStoreTestFixture(t, nil)
	now := time.Unix(1000, 0)
	intent := corestate.PutRecordIntent{Zone: managed, Key: "apps/composed", Type: "application.test", Value: []byte("value")}

	preview, err := store.ApplyCommonLocalIntent(context.Background(), intent, true, now)
	if err != nil {
		t.Fatalf("ApplyCommonLocalIntent(preview): %v", err)
	}
	if preview.Committed || store.Meta().Revision != 0 {
		t.Fatalf("preview/meta = %+v/%+v", preview, store.Meta())
	}
	before, _ := store.Snapshot()
	if _, ok := before.Network.Zones[managed].Records["apps/composed"]; ok {
		t.Fatal("preview appeared in composed read view")
	}

	result, err := store.ApplyCommonLocalIntent(context.Background(), intent, false, now)
	if err != nil {
		t.Fatalf("ApplyCommonLocalIntent(commit): %v", err)
	}
	if !result.Committed || result.Record == nil || result.Record.Version != 1 || store.Meta().Revision != 1 {
		t.Fatalf("commit/meta = %+v/%+v", result, store.Meta())
	}
	after, _ := store.Snapshot()
	if after.Network.Zones[managed].Records["apps/composed"] == nil {
		t.Fatal("committed record missing from composed read view")
	}
	if after.EndpointACLs["admin"].Name != "admin" {
		t.Fatal("common refresh discarded Linux runtime state")
	}
}

func TestComposedDaemonStateStoreRejectsLegacyWriters(t *testing.T) {
	store, _ := newComposedDaemonStateStoreTestFixture(t, nil)
	before, _ := store.Snapshot()
	called := false
	if _, err := store.Update(func(*stateFile) error {
		called = true
		return nil
	}); err == nil {
		t.Fatal("legacy Update succeeded in composed mode")
	}
	if called {
		t.Fatal("legacy Update callback ran in composed mode")
	}
	if _, committed := store.commitNetworkCandidateIfRevision(0, zone.NewNetworkState()); committed {
		t.Fatal("legacy Network candidate committed in composed mode")
	}
	store.ReplaceCommitted(&stateFile{ManagedZone: "replacement.example.", Network: zone.NewNetworkState()})
	after, _ := store.Snapshot()
	if after.ManagedZone != before.ManagedZone {
		t.Fatalf("legacy replacement changed composed owner: %q", after.ManagedZone)
	}
}

func TestComposedDaemonStateStorePersistenceFailureDoesNotRefresh(t *testing.T) {
	wantErr := errors.New("persist failed")
	store, managed := newComposedDaemonStateStoreTestFixture(t, func(context.Context, *corestate.CommitCandidate, corestate.ChangeSet) error {
		return wantErr
	})
	_, err := store.ApplyCommonLocalIntent(context.Background(), corestate.PutRecordIntent{
		Zone: managed, Key: "apps/rejected", Type: "application.test", Value: []byte("value"),
	}, false, time.Unix(1000, 0))
	if !errors.Is(err, wantErr) {
		t.Fatalf("ApplyCommonLocalIntent error = %v", err)
	}
	after, _ := store.Snapshot()
	if store.Meta().Revision != 0 || after.Network.Zones[managed].Records["apps/rejected"] != nil {
		t.Fatalf("failed persistence changed composed view: revision=%d", store.Meta().Revision)
	}
}
