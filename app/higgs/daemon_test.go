package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestNewDaemonServiceDefaultsInterval(t *testing.T) {
	service := newDaemonService(&Runtime{}, &stateFile{}, &syncConfigFile{}, 0)
	if service.Interval != 5*time.Second {
		t.Fatalf("default interval = %s, want 5s", service.Interval)
	}
	if service.Sync == nil {
		t.Fatal("sync runtime is nil")
	}
}

func TestDaemonServiceStateChangedHook(t *testing.T) {
	state := &stateFile{}
	service := newDaemonService(&Runtime{}, state, &syncConfigFile{}, time.Second)
	var called bool
	service.Hooks.OnStateChanged = func(got *stateFile) {
		called = true
		if got != state {
			t.Fatalf("hook got unexpected state pointer")
		}
	}
	service.notifyStateChanged()
	if !called {
		t.Fatal("state changed hook was not called")
	}
}

func TestRootCommandIncludesDaemon(t *testing.T) {
	for _, command := range rootCommand().Commands {
		if command.Name == "daemon" {
			return
		}
	}
	t.Fatal("root command does not include daemon")
}

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
	catofesIssue, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "catofes.", PublicKey: catofesPub})
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
	if _, err := service.handleDelegateIssueEvent(&joinRequest{Version: 1, Zone: "node-b.catofes.", PublicKey: nodeBPub}); err != nil {
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

func TestDaemonRemoteAppliedEventUpdatesPeerState(t *testing.T) {
	state, config := buildTestNetworkState(t)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "higgs.db"),
		Clock:     func() time.Time { return time.Unix(5000, 0) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	var hookCalled bool
	service.Hooks.OnStateChanged = func(*stateFile) {
		hookCalled = true
	}

	result, syncNow, shutdown := service.handleEvent(daemonEvent{
		Type:         daemonEventRemoteApplied,
		SourcePeerID: "node-a.catofes.",
	})
	if result.Error != nil {
		t.Fatalf("handleEvent(remote_applied): %v", result.Error)
	}
	if syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want false/false", syncNow, shutdown)
	}
	if !hookCalled {
		t.Fatal("state changed hook was not called")
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got := latest.SyncPeers["node-a.catofes."].LastUpdateSource; got != "node-a.catofes." {
		t.Fatalf("LastUpdateSource = %q, want node-a.catofes.", got)
	}
}

func TestDaemonControlErrorResponses(t *testing.T) {
	state, config := buildTestNetworkState(t)
	service := newDaemonService(&Runtime{Config: defaultAppConfig()}, state, config, time.Second)

	response := controlRequestViaPipe(t, service, controlRequest{Method: "reload"})
	if response.OK || response.Error == "" {
		t.Fatalf("reload response = %#v, want error", response)
	}

	response = controlRequestViaPipe(t, service, controlRequest{Method: "record_put", Zone: "node-b.catofes."})
	if response.OK || response.Error == "" {
		t.Fatalf("invalid record_put response = %#v, want error", response)
	}

	response = controlRequestViaPipe(t, service, controlRequest{Method: "bogus"})
	if response.OK || response.Error == "" {
		t.Fatalf("unknown method response = %#v, want error", response)
	}

	response = controlRequestViaPipe(t, service, controlRequest{Method: "root_init"})
	if response.OK || response.Error == "" {
		t.Fatalf("root_init response = %#v, want error", response)
	}
}

func TestDaemonControlStatus(t *testing.T) {
	state, config := buildTestNetworkState(t)
	service := newDaemonService(&Runtime{Config: defaultAppConfig()}, state, config, time.Second)
	service.ControlSocketPath = filepath.Join(t.TempDir(), "higgs.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop, err := service.startControlServer(ctx)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("Unix sockets are not permitted in this environment: %v", err)
		}
		t.Fatalf("startControlServer: %v", err)
	}
	defer stop()

	response, err := sendControlRequest(service.ControlSocketPath, controlRequest{Method: "status"})
	if err != nil {
		t.Fatalf("sendControlRequest(status): %v", err)
	}
	if response.PeerID != config.PeerID || response.Message != "daemon online" {
		t.Fatalf("status response = %#v", response)
	}
}

func pumpDaemonEvents(ctx context.Context, service *DaemonService) {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			service.processEvents(ctx)
		}
	}
}

func controlRequestViaPipe(t *testing.T, service *DaemonService, request controlRequest) controlResponse {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		service.handleControlConn(context.Background(), server)
	}()
	if err := json.NewEncoder(client).Encode(request); err != nil {
		t.Fatalf("Encode(request): %v", err)
	}
	var response controlResponse
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatalf("Decode(response): %v", err)
	}
	<-done
	return response
}
