package main

import (
	"context"
	"strings"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	photonservice "github.com/HiggsNet/photon/pkg/service"
)

func TestDaemonIPAMMutationUsesCommittedAuthorityNotDifferentDiskState(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	committed, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(committed): %v", err)
	}
	parent := managed.Parent()
	removeIPAMPoolForTest(committed.Network, parent, "10.0.0.0/16")

	service := newTestDaemonService(rt, committed, syncConfigFromAppConfig(rt.Config, verifiedStateForTest(committed)), time.Second)
	beforeRevision := service.StateStore.Meta().Revision
	result, syncNow, _ := service.handleEvent(daemonEvent{
		Type: daemonEventIPAMMutation,
		IPAM: &ipamMutationRequest{
			Operation: ipamOperationAssignmentCreate,
			Zone:      managed, Prefix: "10.0.1.0/24", Target: managed,
		},
	})
	if result.Error == nil || !strings.Contains(result.Error.Error(), "ipam_assignment_pool_mismatch") {
		t.Fatalf("IPAM mutation error = %v, want daemon committed pool mismatch", result.Error)
	}
	if syncNow {
		t.Fatal("rejected mutation requested sync")
	}
	if got := service.StateStore.Meta().Revision; got != beforeRevision {
		t.Fatalf("revision changed on rejection: before=%d after=%d", beforeRevision, got)
	}
	key, _ := routing.NormalizeIPAMAssignmentKey("10.0.1.0/24")
	view := service.StateStore.common.ReadView()
	if view.State.Network.Zones[managed].Records[key] != nil {
		t.Fatal("rejected assignment entered committed state")
	}
	disk, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(disk): %v", err)
	}
	if disk.Network.Zones[managed].Records[key] != nil {
		t.Fatal("rejected assignment entered disk state")
	}
}

func TestDaemonIPAMMutationPersistsCommittedDecisionWhenDiskIsOlder(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	committed, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(committed): %v", err)
	}
	olderDisk, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(older disk): %v", err)
	}
	removeIPAMPoolForTest(olderDisk.Network, managed.Parent(), "10.0.0.0/16")
	replacePersistedCommonForTest(t, rt, olderDisk)

	service := newTestDaemonService(rt, committed, syncConfigFromAppConfig(rt.Config, verifiedStateForTest(committed)), time.Second)
	result, _, _ := service.handleEvent(daemonEvent{
		Type: daemonEventIPAMMutation,
		IPAM: &ipamMutationRequest{
			Operation: ipamOperationAssignmentCreate,
			Zone:      managed, Prefix: "10.0.1.0/24", Target: managed,
		},
	})
	if result.Error != nil {
		t.Fatalf("IPAM mutation rejected committed authority: %v", result.Error)
	}
	if result.Version != 1 {
		t.Fatalf("version = %d, want 1", result.Version)
	}
	key, _ := routing.NormalizeIPAMAssignmentKey("10.0.1.0/24")
	committedAfter := service.StateStore.common.ReadView()
	if committedAfter.State.Network.Zones[managed].Records[key] == nil {
		t.Fatal("accepted assignment was not published by the common store")
	}
}

func TestDaemonRouteMutationRejectsUsingCommittedActiveStateNotDisk(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if err := applyAuthoritativeTestIntent(state, commonIPAMIntentForTest(t, ipamMutationRequest{
		Operation: ipamOperationAssignmentCreate,
		Zone:      managed, Prefix: "10.0.4.0/24", Target: managed,
	}), rt.Now()); err != nil {
		t.Fatalf("apply assignment: %v", err)
	}
	if err := applyAuthoritativeTestIntent(state, commonRouteIntent(routeMutationRequest{
		Zone: managed, Prefix: "10.0.4.0/24", Active: true,
	}), rt.Now()); err != nil {
		t.Fatalf("apply active route: %v", err)
	}
	activeDisk := cloneStateFile(state)
	if err := applyAuthoritativeTestIntent(state, commonRouteIntent(routeMutationRequest{
		Zone: managed, Prefix: "10.0.4.0/24", Active: false,
	}), rt.Now().Add(time.Second)); err != nil {
		t.Fatalf("withdraw committed route: %v", err)
	}
	replacePersistedCommonForTest(t, rt, activeDisk)

	service := newTestDaemonService(rt, state, syncConfigFromAppConfig(rt.Config, verifiedStateForTest(state)), time.Second)
	before := service.StateStore.Meta()
	result, _, _ := service.handleEvent(daemonEvent{
		Type:  daemonEventRouteMutation,
		Route: &routeMutationRequest{Zone: managed, Prefix: "10.0.4.0/24", Active: false},
	})
	if result.Error == nil || !strings.Contains(result.Error.Error(), "already withdrawn") {
		t.Fatalf("route mutation error = %v, want committed already-withdrawn rejection", result.Error)
	}
	after := service.StateStore.Meta()
	if after.Revision != before.Revision || after.Dirty != before.Dirty {
		t.Fatalf("rejected route changed store meta: before=%+v after=%+v", before, after)
	}
	key, _ := routing.NormalizeRouteAnnouncementKey("10.0.4.0/24")
	disk, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(disk): %v", err)
	}
	ann, err := routing.ParseRouteAnnouncementRecord(disk.Network.Zones[managed].Records[key])
	if err != nil || !ann.Active {
		t.Fatalf("rejected daemon mutation changed disk active route: ann=%+v err=%v", ann, err)
	}
}

func TestDaemonServiceMutationRejectsUsingCommittedAssignmentsNotDisk(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	committed, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(committed): %v", err)
	}
	disk := cloneStateFile(committed)
	if err := applyAuthoritativeTestIntent(disk, commonIPAMIntentForTest(t, ipamMutationRequest{
		Operation: ipamOperationAssignmentCreate,
		Zone:      managed, Prefix: "10.0.5.0/24", Target: managed,
	}), rt.Now()); err != nil {
		t.Fatalf("apply disk assignment: %v", err)
	}
	replacePersistedCommonForTest(t, rt, disk)

	service := newTestDaemonService(rt, committed, syncConfigFromAppConfig(rt.Config, verifiedStateForTest(committed)), time.Second)
	before := service.StateStore.Meta()
	result, _, _ := service.handleEvent(daemonEvent{
		Type: daemonEventServiceMutation,
		Service: &serviceMutationRequest{
			Operation: serviceOperationPublish,
			Endpoints: []photonservice.SOCKS5Endpoint{{Region: "test", Address: "10.0.5.10", Port: 1080}},
		},
	})
	if result.Error == nil || !strings.Contains(result.Error.Error(), "service_address_unauthorized") {
		t.Fatalf("service mutation error = %v, want committed assignment rejection", result.Error)
	}
	after := service.StateStore.Meta()
	if after.Revision != before.Revision || after.Dirty != before.Dirty {
		t.Fatalf("rejected service changed store meta: before=%+v after=%+v", before, after)
	}
	key, _ := photonservice.RecordKey(socks5RecordName)
	reloaded, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(disk): %v", err)
	}
	if reloaded.Network.Zones[managed].Records[key] != nil {
		t.Fatal("rejected service mutation entered disk state")
	}
}

func TestDaemonTypedDryRunDoesNotCommit(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	service := newTestDaemonService(rt, state, syncConfigFromAppConfig(rt.Config, verifiedStateForTest(state)), time.Second)
	before := service.StateStore.Meta().Revision
	result, syncNow, _ := service.handleEvent(daemonEvent{
		Type: daemonEventIPAMMutation,
		IPAM: &ipamMutationRequest{
			Operation: ipamOperationAssignmentCreate,
			Zone:      managed, Prefix: "10.0.2.0/24", Target: managed, DryRun: true,
		},
	})
	if result.Error != nil {
		t.Fatalf("dry-run mutation: %v", result.Error)
	}
	if syncNow {
		t.Fatal("dry-run requested sync")
	}
	if got := service.StateStore.Meta().Revision; got != before {
		t.Fatalf("dry-run revision changed: before=%d after=%d", before, got)
	}
	key, _ := routing.NormalizeIPAMAssignmentKey("10.0.2.0/24")
	view := service.StateStore.common.ReadView()
	if view.State.Network.Zones[managed].Records[key] != nil {
		t.Fatal("dry-run record entered committed state")
	}
}

func TestExplicitDirectAndDaemonIPAMUseSameDomainValidation(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	removeIPAMPoolForTest(state.Network, managed.Parent(), "10.0.0.0/16")
	request := ipamMutationRequest{
		Operation: ipamOperationAssignmentCreate,
		Zone:      managed, Prefix: "10.0.3.0/24", Target: zone.ZonePath(managed),
	}
	directErr := applyAuthoritativeTestIntent(state, commonIPAMIntentForTest(t, request), rt.Now())
	service := newTestDaemonService(rt, state, syncConfigFromAppConfig(rt.Config, verifiedStateForTest(state)), time.Second)
	result, _, _ := service.handleEvent(daemonEvent{Type: daemonEventIPAMMutation, IPAM: &request})
	if directErr == nil || result.Error == nil {
		t.Fatalf("validation results direct=%v daemon=%v, want both rejected", directErr, result.Error)
	}
	if directErr.Error() != result.Error.Error() {
		t.Fatalf("validation diverged: direct=%q daemon=%q", directErr, result.Error)
	}
}

func commonIPAMIntentForTest(t *testing.T, request ipamMutationRequest) corestate.LocalIntent {
	t.Helper()
	intent, err := commonIPAMIntent(request)
	if err != nil {
		t.Fatalf("commonIPAMIntent: %v", err)
	}
	return intent
}

func applyAuthoritativeTestIntent(state *stateFile, intent corestate.LocalIntent, now time.Time) error {
	return applyAuthoritativeTestIntentAs(state, state.ManagedZone, state.ZonePrivateKey, intent, now)
}

func applyAuthoritativeTestIntentAs(state *stateFile, managedZone zone.ZonePath, privateKey []byte, intent corestate.LocalIntent, now time.Time) error {
	store := corestate.NewStoreWithCheckpoint(&corestate.VerifiedState{
		ManagedZone:          managedZone,
		Network:              state.Network,
		TrustedRootPublicKey: append([]byte(nil), state.Network.Zones[zone.RootZone].Authority.Keys[0].Key...),
		RootPrivateKey:       append([]byte(nil), state.RootPrivateKey...),
		IdentityPrivateKey:   append([]byte(nil), privateKey...),
	}, nil, nil)
	if _, err := store.ApplyLocalIntent(context.Background(), intent, now); err != nil {
		return err
	}
	state.Network = store.ReadView().State.Network
	return nil
}

// replacePersistedCommonForTest intentionally makes the detached disk owner
// differ from a daemon's in-memory common owner. These tests exercise that
// conflict boundary, so write the current common schema instead of reviving
// the legacy aggregate buckets.
func replacePersistedCommonForTest(t *testing.T, rt *Runtime, state *stateFile) {
	t.Helper()
	store, err := corestate.OpenBoltStore(rt.StatePath, 0o600, daemonBoltLockTimeout)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	defer store.Close()
	candidate, revision, _, found, err := store.LoadCommon()
	if err != nil || !found {
		t.Fatalf("LoadCommon = found %v err %v", found, err)
	}
	verified := verifiedStateForTest(state)
	verified.TrustedRootPublicKey = append([]byte(nil), candidate.Verified.TrustedRootPublicKey...)
	if err := store.CommitCommon(context.Background(), &corestate.CommitCandidate{
		Verified: verified,
		Gossip:   candidate.Gossip,
	}, corestate.ChangeSet{VerifiedRevision: revision + 1, NetworkChanged: true}); err != nil {
		t.Fatalf("CommitCommon: %v", err)
	}
}

func TestUnavailableMutationControlFailsClosedWithoutDiskWrite(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	rt.DisableControl = false
	t.Setenv("PHOTON_CONTROL_SOCKET", rt.StatePath+".missing.sock")
	request := ipamMutationRequest{
		Operation: ipamOperationAssignmentCreate,
		Zone:      managed, Prefix: "10.0.9.0/24", Target: managed,
	}
	if _, controlled, err := mutateIPAMViaControl(rt, request); err == nil || !controlled {
		t.Fatalf("mutateIPAMViaControl controlled/error = %t/%v, want fail-closed control error", controlled, err)
	}
	key, _ := routing.NormalizeIPAMAssignmentKey(request.Prefix)
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if state.Network.Zones[managed].Records[key] != nil {
		t.Fatal("socket-unavailable mutation wrote the local DB")
	}
}

func TestTypedIPAMControlMethodCommitsDaemonValidatedRequest(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	service := newTestDaemonService(rt, state, syncConfigFromAppConfig(rt.Config, verifiedStateForTest(state)), time.Second)
	ctx := t.Context()
	go pumpDaemonEvents(ctx, service)

	response := controlRequestViaPipe(t, service, controlRequest{
		Method: "ipam_mutate",
		IPAM: &ipamMutationRequest{
			Operation: ipamOperationAssignmentCreate,
			Zone:      managed, Prefix: "10.0.8.0/24", Target: managed,
		},
	})
	if !response.OK || response.Version != 1 {
		t.Fatalf("ipam_mutate response = %+v", response)
	}
	key, _ := routing.NormalizeIPAMAssignmentKey("10.0.8.0/24")
	view := service.StateStore.common.ReadView()
	if view.State.Network.Zones[managed].Records[key] == nil {
		t.Fatal("typed control mutation did not enter committed state")
	}
}

func TestDaemonRawRecordPutRejectsReservedNamespaceWithoutRevision(t *testing.T) {
	state, config := buildTestNetworkState(t)
	service := newTestDaemonService(&Runtime{Config: defaultAppConfig(), Clock: time.Now}, state, config, time.Second)
	before := service.StateStore.Meta().Revision
	result, syncNow, _ := service.handleEvent(daemonEvent{
		Type: daemonEventRecordPut,
		RecordPut: &daemonRecordPut{
			Zone: zone.ZonePath("node-b.catofes."),
			Key:  routing.RecordKeyPrefixRoutes + "10.0.0.0_24",
			Type: "application.fake",
		},
	})
	if result.Error == nil || !strings.Contains(result.Error.Error(), "daemon-owned") {
		t.Fatalf("reserved record_put error = %v", result.Error)
	}
	if syncNow {
		t.Fatal("rejected raw record requested sync")
	}
	if got := service.StateStore.Meta().Revision; got != before {
		t.Fatalf("revision changed on reserved raw record: before=%d after=%d", before, got)
	}
}
