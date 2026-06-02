package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
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
