package main

import (
	"context"
	"crypto/ed25519"
	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDaemonRecordPutEventSerializesWrite(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)

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
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.Network.Zones["node-b.catofes."].Records["identity"] == nil {
		t.Fatalf("record was not persisted")
	}
}

func TestDaemonRecordPutUsesStateStoreWhileLiveStateLocked(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(2100, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)

	unlock := service.lockState()
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
		t.Fatal("live state pointer did not transfer to committed state")
	}
	if got := current.Network.Zones["node-b.catofes."].Records["locked-record"]; got == nil {
		unlock()
		t.Fatal("transferred live state missing locked record")
	}
	unlock()
	if version != 1 {
		t.Fatalf("version = %d, want 1", version)
	}
	snapshot, _ := service.StateStore.Snapshot()
	if got := snapshot.Network.Zones["node-b.catofes."].Records["locked-record"]; got == nil {
		t.Fatal("committed snapshot missing locked record")
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got := latest.Network.Zones["node-b.catofes."].Records["locked-record"]; got == nil {
		t.Fatal("persisted state missing locked record")
	}
}

func TestDaemonEndpointTimerUsesStateStoreWhileLiveStateLocked(t *testing.T) {
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
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)

	unlock := service.lockState()
	if err := service.handleEndpointTimerEvent(); err != nil {
		unlock()
		t.Fatalf("handleEndpointTimerEvent: %v", err)
	}
	current := service.currentState()
	if current == state {
		unlock()
		t.Fatal("live state pointer did not transfer to committed state")
	}
	if got := current.Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP]; got == nil {
		unlock()
		t.Fatal("transferred live state missing endpoint record")
	}
	unlock()

	snapshot, _ := service.StateStore.Snapshot()
	if got := snapshot.Network.Zones[state.ManagedZone].Records[gossip.EndpointRecordKeyUDP]; got == nil {
		t.Fatal("committed snapshot missing endpoint record")
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
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
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	sr := newSyncRuntime(state, config, nil, rt)
	if err := sr.publishIPsecRecords(); err != nil {
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
	service := newDaemonService(rt, latest, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver
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
	rotatedState, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(rotated): %v", err)
	}
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

func TestDaemonIPsecPortRotateUsesStateStoreWhileLiveStateLocked(t *testing.T) {
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
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)

	unlock := service.lockState()
	result, err := service.handleIPsecPortRotateEvent()
	if err != nil {
		unlock()
		t.Fatalf("handleIPsecPortRotateEvent: %v", err)
	}
	current := service.currentState()
	if current == state {
		unlock()
		t.Fatal("live state pointer did not transfer to committed state")
	}
	if got := current.IPsecPortRecord; got == nil || got.Generation != result.CurrentGeneration {
		unlock()
		t.Fatalf("transferred live IPsecPortRecord = %#v, want generation %d", got, result.CurrentGeneration)
	}
	unlock()
	if result == nil || result.CurrentGeneration == 0 {
		t.Fatalf("rotate result = %#v", result)
	}
	snapshot, _ := service.StateStore.Snapshot()
	if snapshot.IPsecPortRecord == nil || snapshot.IPsecPortRecord.Generation != result.CurrentGeneration {
		t.Fatalf("committed IPsecPortRecord = %#v, want generation %d", snapshot.IPsecPortRecord, result.CurrentGeneration)
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.IPsecPortRecord == nil || latest.IPsecPortRecord.Generation != result.CurrentGeneration {
		t.Fatalf("persisted IPsecPortRecord = %#v, want generation %d", latest.IPsecPortRecord, result.CurrentGeneration)
	}
}

func TestDaemonConcurrentRecordPutEventsAreSerialized(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(3000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pumpDaemonEvents(ctx, service)

	const writes = 8
	var wg sync.WaitGroup
	errs := make(chan error, writes)
	for i := 0; i < writes; i++ {
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
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
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

func TestDaemonRecordPutReloadsLatestStateBeforeSave(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4000, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)

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
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(latest): %v", err)
	}
	records := latest.Network.Zones["node-b.catofes."].Records
	if records["external"] == nil {
		t.Fatalf("external record was overwritten by stale daemon state")
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
	service := newDaemonService(rootRT, rootState, &syncConfigFile{PeerID: "node-admin", ListenAddr: "127.0.0.1:0"}, time.Second)

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

	catofesKey := &privateKeyFile{Type: "higgs.ed25519.private.v1", PublicKey: catofesPub, PrivateKey: catofesPriv}
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
	latest, err := rootRT.LoadState()
	if err != nil {
		t.Fatalf("LoadState(latest): %v", err)
	}
	parent := latest.Network.Zones[zone.ZonePath("catofes.")]
	if parent == nil || parent.Revocations["node-b.catofes."] == nil {
		t.Fatalf("node-b revocation was not persisted")
	}
	if parent.Delegations["node-b.catofes."] != nil {
		t.Fatalf("node-b delegation still active after revoke")
	}
}

func TestDaemonDelegateIssueUsesStateStoreWhileLiveStateLocked(t *testing.T) {
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
	service := newDaemonService(rt, state, &syncConfigFile{PeerID: "node-admin", ListenAddr: "127.0.0.1:0"}, time.Second)
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	unlock := service.lockState()
	result, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "catofes.", PublicKey: pub}, nil)
	if err != nil {
		unlock()
		t.Fatalf("handleDelegateIssueEvent: %v", err)
	}
	current := service.currentState()
	if current == state {
		unlock()
		t.Fatal("live state pointer did not transfer to committed state")
	}
	if got := current.Network.Zones[zone.RootZone].Delegations["catofes."]; got == nil {
		unlock()
		t.Fatal("transferred live state missing catofes delegation")
	}
	unlock()
	if result == nil || result.Bundle == nil || result.Bundle.Zone != "catofes." {
		t.Fatalf("delegate issue result = %#v", result)
	}
	snapshot, _ := service.StateStore.Snapshot()
	if got := snapshot.Network.Zones[zone.RootZone].Delegations["catofes."]; got == nil {
		t.Fatal("committed snapshot missing catofes delegation")
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(latest): %v", err)
	}
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
	service := newDaemonService(rt, state, &syncConfigFile{PeerID: "zone-catofes-admin", ListenAddr: "127.0.0.1:0"}, time.Second)

	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	catofesIssue, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "catofes.", PublicKey: catofesPub}, nil)
	if err != nil {
		t.Fatalf("handleDelegateIssueEvent(catofes): %v", err)
	}
	if _, err := service.handleJoinAcceptEvent(catofesIssue.Bundle, &privateKeyFile{Type: "higgs.ed25519.private.v1", PublicKey: catofesPub, PrivateKey: catofesPriv}); err != nil {
		t.Fatalf("handleJoinAcceptEvent(catofes): %v", err)
	}

	nodeBPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node-b): %v", err)
	}
	if _, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "node-b.catofes.", PublicKey: nodeBPub}, nil); err != nil {
		t.Fatalf("handleDelegateIssueEvent(node-b): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(latest): %v", err)
	}
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
