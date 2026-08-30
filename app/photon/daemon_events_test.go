package main

import (
	"context"
	"crypto/ed25519"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestDaemonRecordPutEventSerializesWrite(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)

	result, syncNow, shutdown := service.handleEvent(daemonEvent{
		Type: daemonEventRecordPut,
		RecordPut: &daemonRecordPut{
			Zone:  zone.ZonePath("node-b.catofes."),
			Key:   "identity",
			Value: []byte("node-b"),
			Type:  "policy.string",
		},
	})
	if result.Error != nil {
		t.Fatalf("handleEvent(record_put): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	if result.Version != 1 {
		t.Fatalf("version = %d, want 1", result.Version)
	}
	latest := service.currentState()
	if latest.Network.Zones["node-b.catofes."].Records["identity"] == nil {
		t.Fatalf("record was not persisted")
	}
}

func TestDaemonRecordPutUsesStateStoreWhileConstructorInputLocked(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2100, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)

	state.Lock()
	unlock := state.Unlock
	version, err := service.handleRecordPutEvent(&daemonRecordPut{
		Zone:  zone.ZonePath("node-b.catofes."),
		Key:   "locked-record",
		Value: []byte("store"),
		Type:  "policy.string",
	})
	if err != nil {
		unlock()
		t.Fatalf("handleRecordPutEvent: %v", err)
	}
	current := service.currentState()
	if current == state {
		unlock()
		t.Fatal("committed snapshot still aliases constructor input")
	}
	if got := current.Network.Zones["node-b.catofes."].Records["locked-record"]; got == nil {
		unlock()
		t.Fatal("committed state missing locked record")
	}
	unlock()
	if version != 1 {
		t.Fatalf("version = %d, want 1", version)
	}
	snapshot, _ := snapshotTestDaemonState(service.StateStore)
	if got := snapshot.Network.Zones["node-b.catofes."].Records["locked-record"]; got == nil {
		t.Fatal("committed snapshot missing locked record")
	}
	latest := service.currentState()
	if got := latest.Network.Zones["node-b.catofes."].Records["locked-record"]; got == nil {
		t.Fatal("persisted state missing locked record")
	}
}

func TestDaemonEventLoopRecordPutDoesNotWaitForConstructorInputLock(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2125, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)

	reply := make(chan daemonEventResult, 1)
	service.Events <- daemonEvent{
		Type: daemonEventRecordPut,
		RecordPut: &daemonRecordPut{
			Zone:  zone.ZonePath("node-b.catofes."),
			Key:   "event-loop-record",
			Value: []byte("store"),
			Type:  "policy.string",
		},
		Reply: reply,
	}
	state.Lock()
	unlock := state.Unlock
	done := make(chan daemonEventResult, 1)
	go func() {
		service.processEvents(context.Background())
		done <- <-reply
	}()

	select {
	case result := <-done:
		if result.Error != nil {
			unlock()
			t.Fatalf("processEvents(record_put): %v", result.Error)
		}
	case <-time.After(time.Second):
		unlock()
		t.Fatal("record_put event blocked behind detached constructor-input lock")
	}
	current := service.currentState()
	if current == state {
		unlock()
		t.Fatal("committed snapshot still aliases constructor input")
	}
	unlock()

	snapshot, _ := snapshotTestDaemonState(service.StateStore)
	if got := snapshot.Network.Zones["node-b.catofes."].Records["event-loop-record"]; got == nil {
		t.Fatal("committed snapshot missing event-loop record")
	}
}

func TestDaemonEndpointTimerUsesStateStoreWhileConstructorInputLocked(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	config.ListenAddr = "198.51.100.20:4242"
	now := time.Unix(2150, 0)
	appConfig := defaultAppConfig()
	appConfig.ListenAddr = config.ListenAddr
	appConfig.AdvertiseAddrs = []string{"198.51.100.20:4242"}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)

	state.Lock()
	unlock := state.Unlock
	if _, err := service.handleEndpointTimerEvent(); err != nil {
		unlock()
		t.Fatalf("handleEndpointTimerEvent: %v", err)
	}
	current := service.currentState()
	if current == state {
		unlock()
		t.Fatal("committed snapshot still aliases constructor input")
	}
	if got := current.Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP]; got == nil {
		unlock()
		t.Fatal("committed state missing endpoint record")
	}
	unlock()

	snapshot, _ := snapshotTestDaemonState(service.StateStore)
	if got := snapshot.Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP]; got == nil {
		t.Fatal("committed snapshot missing endpoint record")
	}
	latest := service.currentState()
	if got := latest.Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP]; got == nil {
		t.Fatal("persisted state missing endpoint record")
	}
}

func TestDaemonIPsecPortRotateEventTriggersDataPlaneReconcile(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	now := time.Unix(2000, 0)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	appConfig.IPsec.PortMode = ipsec.PortModeRange
	appConfig.IPsec.PortRange = ipsec.PortRange{From: 30000, To: 30099}
	appConfig.IPsec.PortPreviousGrace = 2 * time.Hour
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	sr := newSyncRuntime(config, nil, rt)
	if err := sr.publishIPsecRecords(state); err != nil {
		t.Fatalf("publishIPsecRecords: %v", err)
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState(published ports): %v", err)
	}
	first, err := ipsec.ParsePortRecord(state.Network.Zones[state.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord(first): %v", err)
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	driver := &countingIPsecDriver{}
	service := newTestDaemonService(rt, latest, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)
	reply := make(chan daemonEventResult, 1)
	service.Events <- daemonEvent{Type: daemonEventIPsecPortRotate, Reply: reply}

	syncNow, shutdown, ipsecFlushed, _, firewallFlushed := service.processEvents(context.Background())
	if !syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	if !firewallFlushed || !ipsecFlushed {
		t.Fatalf("firewallFlushed/ipsecFlushed = %v/%v, want true/true", firewallFlushed, ipsecFlushed)
	}
	result := <-reply
	if result.Error != nil {
		t.Fatalf("ipsec port rotate event: %v", result.Error)
	}
	if result.PortRotate == nil || result.PortRotate.CurrentGeneration != first.Current.Generation+1 {
		t.Fatalf("port rotate result = %+v, want generation %d", result.PortRotate, first.Current.Generation+1)
	}
	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want 1", driver.listCalls)
	}
	rotatedState := service.currentState()
	rotated, err := ipsec.ParsePortRecord(rotatedState.Network.Zones[rotatedState.ManagedZone].Records[ipsec.RecordKeyPorts])
	if err != nil {
		t.Fatalf("ParsePortRecord(rotated): %v", err)
	}
	if rotated.Current.Generation != first.Current.Generation+1 {
		t.Fatalf("generation = %d, want %d", rotated.Current.Generation, first.Current.Generation+1)
	}
	if len(rotated.Previous) != 1 || rotated.Previous[0].Generation != first.Current.Generation {
		t.Fatalf("previous grace = %+v, want generation %d", rotated.Previous, first.Current.Generation)
	}
}

func TestDaemonIPsecPortRotateUsesStateStoreWhileConstructorInputLocked(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	now := time.Unix(2300, 0)
	appConfig := defaultAppConfig()
	appConfig.IPsec.PortMode = ipsec.PortModeRange
	appConfig.IPsec.PortRange = ipsec.PortRange{From: 31000, To: 31099}
	appConfig.IPsec.PortPreviousGrace = time.Hour
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)

	state.Lock()
	unlock := state.Unlock
	result, err := service.handleIPsecPortRotateEvent()
	if err != nil {
		unlock()
		t.Fatalf("handleIPsecPortRotateEvent: %v", err)
	}
	current := service.currentState()
	if current == state {
		unlock()
		t.Fatal("committed snapshot still aliases constructor input")
	}
	if got := current.IPsecPortRecord; got == nil || got.Generation != result.CurrentGeneration {
		unlock()
		t.Fatalf("transferred live IPsecPortRecord = %#v, want generation %d", got, result.CurrentGeneration)
	}
	unlock()
	if result == nil || result.CurrentGeneration == 0 {
		t.Fatalf("rotate result = %#v", result)
	}
	snapshot, _ := snapshotTestDaemonState(service.StateStore)
	if snapshot.IPsecPortRecord == nil || snapshot.IPsecPortRecord.Generation != result.CurrentGeneration {
		t.Fatalf("committed IPsecPortRecord = %#v, want generation %d", snapshot.IPsecPortRecord, result.CurrentGeneration)
	}
	latest := service.currentState()
	if latest.IPsecPortRecord == nil || latest.IPsecPortRecord.Generation != result.CurrentGeneration {
		t.Fatalf("persisted IPsecPortRecord = %#v, want generation %d", latest.IPsecPortRecord, result.CurrentGeneration)
	}
}

func TestDaemonConcurrentRecordPutEventsAreSerialized(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(3000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)
	ctx := t.Context()
	go pumpDaemonEvents(ctx, service)

	const writes = 8
	var wg sync.WaitGroup
	errs := make(chan error, writes)
	for i := range writes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			result := service.enqueueEvent(ctx, daemonEvent{
				Type: daemonEventRecordPut,
				RecordPut: &daemonRecordPut{
					Zone:  zone.ZonePath("node-b.catofes."),
					Key:   "identity",
					Value: []byte{byte('a' + i)},
					Type:  "policy.string",
				},
			})
			errs <- result.Error
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("record_put event failed: %v", err)
		}
	}
	latest := service.currentState()
	record := latest.Network.Zones["node-b.catofes."].Records["identity"]
	if record == nil {
		t.Fatal("identity record missing")
	}
	if record.Version != writes {
		t.Fatalf("latest version = %d, want %d", record.Version, writes)
	}
	if history := latest.Network.Zones["node-b.catofes."].RecordHistory["identity"]; len(history) != writes-1 {
		t.Fatalf("history length = %d, want %d", len(history), writes-1)
	}
}

func TestDaemonRecordPutKeepsCommittedStateAuthoritativeOverExternalDiskWrite(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)

	external, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(external): %v", err)
	}
	externalRecord, err := buildSignedRecordAt(external, "node-b.catofes.", "external", []byte("kept"), "policy.string", now)
	if err != nil {
		t.Fatalf("buildSignedRecordAt(external): %v", err)
	}
	if err := external.Network.Put(externalRecord); err != nil {
		t.Fatalf("Put(external): %v", err)
	}
	if err := rt.SaveState(external); err != nil {
		t.Fatalf("SaveState(external): %v", err)
	}

	result, _, _ := service.handleEvent(daemonEvent{
		Type: daemonEventRecordPut,
		RecordPut: &daemonRecordPut{
			Zone:  zone.ZonePath("node-b.catofes."),
			Key:   "daemon",
			Value: []byte("new"),
			Type:  "policy.string",
		},
	})
	if result.Error != nil {
		t.Fatalf("handleEvent(record_put): %v", result.Error)
	}
	latest := service.currentState()
	records := latest.Network.Zones["node-b.catofes."].Records
	if records["external"] != nil {
		t.Fatalf("out-of-band disk record replaced daemon committed authority")
	}
	if records["daemon"] == nil {
		t.Fatalf("daemon record missing")
	}
}

func TestBuildSignedRecordReturnsErrorWithoutLocalSigner(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.ManagedZone = "node-a.catofes."
	state.ZonePrivateKey = nil

	_, err := buildSignedRecordAt(state, "node-b.catofes.", "identity", []byte("node-b"), "policy.string", time.Unix(1, 0))
	if err == nil || !strings.Contains(err.Error(), "no local signing key") {
		t.Fatalf("buildSignedRecordAt error = %v, want missing signer", err)
	}
}

func TestDaemonAdminEventsIssueAcceptAndRevoke(t *testing.T) {
	now := time.Unix(6000, 0)
	rootRT := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "root.db"),
		Clock:     func() time.Time { return now },
	}
	if _, err := initRootStateInRuntime(rootRT); err != nil {
		t.Fatalf("initRootStateInRuntime: %v", err)
	}
	rootState, err := rootRT.LoadState()
	if err != nil {
		t.Fatalf("LoadState(root): %v", err)
	}
	service := newTestDaemonService(rootRT, rootState, &syncConfigFile{PeerID: "node-admin", ListenAddr: "127.0.0.1:0"}, time.Second)

	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	catofesRequest := &joinRequest{Version: 1, Zone: "catofes.", PublicKey: catofesPub}
	result, syncNow, shutdown := service.handleEvent(daemonEvent{Type: daemonEventDelegateIssue, JoinRequest: catofesRequest})
	if result.Error != nil {
		t.Fatalf("handleEvent(delegate_issue catofes): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("delegate_issue syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	if result.JoinBundle == nil || result.JoinBundle.Zone != "catofes." {
		t.Fatalf("delegate_issue bundle = %#v", result.JoinBundle)
	}

	catofesKey := &privateKeyFile{Type: "photon.ed25519.private.v1", PublicKey: catofesPub, PrivateKey: catofesPriv}
	joinState := &stateFile{Network: zone.NewNetworkState()}
	service = newTestDaemonService(rootRT, joinState, &syncConfigFile{PeerID: "catofes.", ListenAddr: "127.0.0.1:0"}, time.Second)
	result, syncNow, shutdown = service.handleEvent(daemonEvent{
		Type:       daemonEventJoinAccept,
		JoinBundle: result.JoinBundle,
		PrivateKey: catofesKey,
	})
	if result.Error != nil {
		t.Fatalf("handleEvent(join_accept catofes): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("join_accept syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	if result.Zone != "catofes." {
		t.Fatalf("join_accept zone = %s, want catofes.", result.Zone)
	}

	nodePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}
	nodeRequest := &joinRequest{Version: 1, Zone: "node-b.catofes.", PublicKey: nodePub}
	result, _, _ = service.handleEvent(daemonEvent{Type: daemonEventDelegateIssue, JoinRequest: nodeRequest})
	if result.Error != nil {
		t.Fatalf("handleEvent(delegate_issue node-b): %v", result.Error)
	}
	if result.JoinBundle == nil || result.JoinBundle.Zone != "node-b.catofes." {
		t.Fatalf("node-b bundle = %#v", result.JoinBundle)
	}

	result, syncNow, shutdown = service.handleEvent(daemonEvent{
		Type:   daemonEventDelegateRevoke,
		Zone:   "node-b.catofes.",
		Reason: "test revoke",
	})
	if result.Error != nil {
		t.Fatalf("handleEvent(delegate_revoke): %v", result.Error)
	}
	if !syncNow || shutdown {
		t.Fatalf("delegate_revoke syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	latest := service.currentState()
	parent := latest.Network.Zones[zone.ZonePath("catofes.")]
	if parent == nil || parent.Revocations["node-b.catofes."] == nil {
		t.Fatalf("node-b revocation was not persisted")
	}
	if parent.Delegations["node-b.catofes."] != nil {
		t.Fatalf("node-b delegation still active after revoke")
	}
}

func TestDaemonDelegateIssueUsesStateStoreWhileConstructorInputLocked(t *testing.T) {
	now := time.Unix(6100, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "root.db"),
		Clock:     func() time.Time { return now },
	}
	if _, err := initRootStateInRuntime(rt); err != nil {
		t.Fatalf("initRootStateInRuntime: %v", err)
	}
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(root): %v", err)
	}
	service := newTestDaemonService(rt, state, &syncConfigFile{PeerID: "node-admin", ListenAddr: "127.0.0.1:0"}, time.Second)
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	state.Lock()
	unlock := state.Unlock
	result, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "catofes.", PublicKey: pub}, nil)
	if err != nil {
		unlock()
		t.Fatalf("handleDelegateIssueEvent: %v", err)
	}
	current := service.currentState()
	if current == state {
		unlock()
		t.Fatal("committed snapshot still aliases constructor input")
	}
	if got := current.Network.Zones[zone.RootZone].Delegations["catofes."]; got == nil {
		unlock()
		t.Fatal("committed state missing catofes delegation")
	}
	unlock()
	if result == nil || result.Bundle == nil || result.Bundle.Zone != "catofes." {
		t.Fatalf("delegate issue result = %#v", result)
	}
	snapshot, _ := snapshotTestDaemonState(service.StateStore)
	if got := snapshot.Network.Zones[zone.RootZone].Delegations["catofes."]; got == nil {
		t.Fatal("committed snapshot missing catofes delegation")
	}
	latest := service.currentState()
	if got := latest.Network.Zones[zone.RootZone].Delegations["catofes."]; got == nil {
		t.Fatal("persisted state missing catofes delegation")
	}
}

func TestDaemonConcurrentAdminAndRecordEventsPreserveState(t *testing.T) {
	now := time.Unix(7000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "catofes.db"),
		Clock:     func() time.Time { return now },
	}
	if _, err := initRootStateInRuntime(rt); err != nil {
		t.Fatalf("initRootStateInRuntime: %v", err)
	}
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(root): %v", err)
	}
	service := newTestDaemonService(rt, state, &syncConfigFile{PeerID: "zone-catofes-admin", ListenAddr: "127.0.0.1:0"}, time.Second)

	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	catofesIssue, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "catofes.", PublicKey: catofesPub}, nil)
	if err != nil {
		t.Fatalf("handleDelegateIssueEvent(catofes): %v", err)
	}
	service = newTestDaemonService(rt, &stateFile{Network: zone.NewNetworkState()}, &syncConfigFile{PeerID: "catofes.", ListenAddr: "127.0.0.1:0"}, time.Second)
	if _, err := service.handleJoinAcceptEvent(catofesIssue.Bundle, &privateKeyFile{Type: "photon.ed25519.private.v1", PublicKey: catofesPub, PrivateKey: catofesPriv}); err != nil {
		t.Fatalf("handleJoinAcceptEvent(catofes): %v", err)
	}

	nodeBPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}
	if _, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "node-b.catofes.", PublicKey: nodeBPub}, nil); err != nil {
		t.Fatalf("handleDelegateIssueEvent(node-b): %v", err)
	}

	ctx := t.Context()
	go pumpDaemonEvents(ctx, service)

	nodeCPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-c): %v", err)
	}
	events := []daemonEvent{
		{
			Type: daemonEventRecordPut,
			RecordPut: &daemonRecordPut{
				Zone:  "catofes.",
				Key:   "admin-note",
				Value: []byte("kept"),
				Type:  "policy.string",
			},
		},
		{
			Type:        daemonEventDelegateIssue,
			JoinRequest: &joinRequest{Version: 1, Zone: "node-c.catofes.", PublicKey: nodeCPub},
		},
		{
			Type:   daemonEventDelegateRevoke,
			Zone:   "node-b.catofes.",
			Reason: "concurrent test",
		},
	}
	errs := make(chan error, len(events))
	var wg sync.WaitGroup
	for _, event := range events {
		wg.Add(1)
		go func(event daemonEvent) {
			defer wg.Done()
			errs <- service.enqueueEvent(ctx, event).Error
		}(event)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent daemon event failed: %v", err)
		}
	}

	latest := service.currentState()
	catofes := latest.Network.Zones[zone.ZonePath("catofes.")]
	if catofes.Records["admin-note"] == nil {
		t.Fatalf("record_put result missing after concurrent admin events")
	}
	if catofes.Delegations["node-c.catofes."] == nil {
		t.Fatalf("delegate_issue result missing after concurrent record_put")
	}
	if catofes.Revocations["node-b.catofes."] == nil {
		t.Fatalf("delegate_revoke result missing after concurrent record_put")
	}
}

func TestDaemonEndpointTimerNoChangeSkipsFlushAndSync(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	config.ListenAddr = "198.51.100.20:4242"
	now := time.Unix(2200, 0)
	appConfig := defaultAppConfig()
	appConfig.ListenAddr = config.ListenAddr
	appConfig.AdvertiseAddrs = []string{"198.51.100.20:4242"}
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	oldCollect := collectSyncLocalEndpoints
	collectSyncLocalEndpoints = func(port uint16, _ []string, _ []string, _ time.Duration, _ bool) ([]gossip.LocalEndpoint, error) {
		return []gossip.LocalEndpoint{{IP: net.ParseIP("198.51.100.20"), Port: port, Scope: "global", Source: gossip.SourceAdvertise}}, nil
	}
	t.Cleanup(func() { collectSyncLocalEndpoints = oldCollect })
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)

	// First publish: records are created, state is flushed.
	if _, err := service.handleEndpointTimerEvent(); err != nil {
		t.Fatalf("first handleEndpointTimerEvent: %v", err)
	}

	// Reset flush tracking and capture the revision after the initial publish.
	var flushed []string
	service.Hooks.OnReconcileFlush = func(layer string) {
		flushed = append(flushed, layer)
	}
	beforeRev := service.StateStore.Meta().Revision

	// Second publish at the same timestamp: nothing changed, so it should not
	// trigger a sync, layer flush, or state-store revision bump.
	result, syncNow, shutdown := service.handleEvent(daemonEvent{Type: daemonEventEndpointTimer})
	if result.Error != nil {
		t.Fatalf("second handleEvent(endpoint): %v", result.Error)
	}
	if syncNow {
		t.Fatalf("syncNow = true, want false on no-op endpoint timer")
	}
	if shutdown {
		t.Fatalf("shutdown = true, want false")
	}
	if len(flushed) != 0 {
		t.Fatalf("layer flushes on no-op endpoint timer: %v", flushed)
	}
	if afterRev := service.StateStore.Meta().Revision; afterRev != beforeRev {
		t.Fatalf("state store revision changed on no-op endpoint timer: before=%d after=%d", beforeRev, afterRev)
	}
}

func TestPrepareStartupStateCommitsAdmissionOnceWithoutMutatingConstructorInput(t *testing.T) {
	dir := t.TempDir()
	state, _ := buildPendingAutoJoinState(t, dir, "node-b.catofes.", false)
	state.Admission = nil
	now := time.Unix(7250, 0)
	rt := &Runtime{
		StatePath: filepath.Join(dir, "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	config := &syncConfigFile{
		PeerID:                 "node-b.catofes.",
		ListenAddr:             "127.0.0.1:0",
		DisableEndpointPublish: true,
	}
	service := newTestDaemonService(rt, state, config, time.Second)
	beforeRev := service.StateStore.Meta().Revision

	changed, err := service.prepareStartupState()
	if err != nil {
		t.Fatalf("prepareStartupState: %v", err)
	}
	if !changed {
		t.Fatal("prepareStartupState changed = false, want admission commit")
	}
	if state.Admission != nil {
		t.Fatal("prepareStartupState mutated the detached constructor input")
	}
	committed, rev := snapshotTestDaemonState(service.StateStore)
	if rev != beforeRev {
		t.Fatalf("verified revision = %d, want runtime-only startup to keep %d", rev, beforeRev)
	}
	if committed.Admission == nil || !committed.Admission.Pending || committed.Admission.PendingSinceUnix != now.Unix() {
		t.Fatalf("committed admission = %+v, want pending startup diagnosis", committed.Admission)
	}
	if current := service.currentState(); current == state || current.Admission == nil || !current.Admission.Pending {
		t.Fatalf("current admission = %+v, want committed state", current.Admission)
	}
	reloaded := service.currentState()
	if reloaded.Admission == nil || !reloaded.Admission.Pending {
		t.Fatalf("persisted admission = %+v, want pending", reloaded.Admission)
	}

	changed, err = service.prepareStartupState()
	if err != nil {
		t.Fatalf("prepareStartupState(second): %v", err)
	}
	if changed {
		t.Fatal("prepareStartupState(second) changed = true, want no-op")
	}
	if got := service.StateStore.Meta().Revision; got != rev {
		t.Fatalf("state revision after no-op = %d, want %d", got, rev)
	}
}

func TestDaemonEndpointTimerRefreshDueStillTriggersSync(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.ManagedZone = "node-b.catofes."
	config.PeerID = string(state.ManagedZone)
	config.ListenAddr = "198.51.100.20:4242"
	config.AdvertiseAddrs = []string{"198.51.100.20:4242"}
	config.EndpointRefresh = 30 * time.Minute
	config.EndpointTTL = time.Hour

	now := time.Unix(1000, 0)
	appConfig := defaultAppConfig()
	appConfig.ListenAddr = config.ListenAddr
	appConfig.AdvertiseAddrs = []string{"198.51.100.20:4242"}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)

	// First publish: record is created.
	if _, err := service.handleEndpointTimerEvent(); err != nil {
		t.Fatalf("first handleEndpointTimerEvent: %v", err)
	}
	first := service.currentState().Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP]
	if first == nil {
		t.Fatal("first endpoint record missing")
	}

	// Second publish before refresh interval: no-op, no sync trigger.
	now = time.Unix(1300, 0)
	result, syncNow, shutdown := service.handleEvent(daemonEvent{Type: daemonEventEndpointTimer})
	if result.Error != nil {
		t.Fatalf("second handleEvent(endpoint): %v", result.Error)
	}
	if shutdown {
		t.Fatalf("shutdown = true, want false")
	}
	if syncNow {
		t.Fatalf("syncNow = true, want false before refresh interval")
	}

	// Third publish after refresh interval: record should be refreshed and sync
	// should be triggered so gossip can propagate the new lease timestamp.
	now = time.Unix(2800, 0)
	result, syncNow, shutdown = service.handleEvent(daemonEvent{Type: daemonEventEndpointTimer})
	if result.Error != nil {
		t.Fatalf("third handleEvent(endpoint): %v", result.Error)
	}
	if shutdown {
		t.Fatalf("shutdown = true, want false")
	}
	if !syncNow {
		t.Fatalf("syncNow = false, want true after refresh interval")
	}
	third := service.currentState().Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP]
	if third.Version != first.Version+1 {
		t.Fatalf("third version = %d, want %d (refreshed)", third.Version, first.Version+1)
	}
	refreshed := endpointRecordFromState(t, service.currentState(), state.ManagedZone)
	if refreshed.UpdatedAt != 2800 {
		t.Fatalf("refreshed updated_at = %d, want 2800", refreshed.UpdatedAt)
	}
}
