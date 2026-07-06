package main

import (
	"context"
	"errors"
	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDaemonControlErrorResponses(t *testing.T) {
	state, config := buildTestNetworkState(t)
	service := newDaemonService(&Runtime{Config: defaultAppConfig()}, state, config, time.Second)

	response := controlRequestViaPipe(t, service, controlRequest{Method: "record_put", Zone: "node-b.catofes."})
	if response.OK || response.Error == "" {
		t.Fatalf("invalid record_put response = %#v, want error", response)
	}

	response = controlRequestViaPipe(t, service, controlRequest{Method: "record_get", Zone: "node-b.catofes."})
	if response.OK || response.Error == "" {
		t.Fatalf("invalid record_get response = %#v, want error", response)
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

func TestDaemonControlRoutingReload(t *testing.T) {
	state, config := buildTestNetworkStateForRouting(t)
	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	rt := &Runtime{Config: appConfig, StatePath: filepath.Join(t.TempDir(), "higgs.db")}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.routingDirty = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pumpDaemonEvents(ctx, service)

	response := controlRequestViaPipe(t, service, controlRequest{Method: "routing_reload"})
	if !response.OK || response.Message != "routing reloaded" {
		t.Fatalf("routing_reload response = %#v", response)
	}
	if service.routingDirty {
		t.Fatalf("routingDirty should be cleared after synchronous routing_reload")
	}
}

func TestDaemonControlBirdDump(t *testing.T) {
	state, config := buildTestNetworkStateForRouting(t)
	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"higgstesth2": {Kind: ipsec.NetNSName, Name: "higgstesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{
		ID:            "main",
		NetNS:         "higgstesth2",
		Enabled:       boolPtr(true),
		Mode:          ipsec.RoutingModeManaged,
		ControlSocket: "/run/higgs/bird-higgstesth2.ctl",
	}}, appConfig.Netns, appConfig.DataDir)

	client := &fakeBirdClient{raw: map[string]string{
		"show route all": "Table master4:\n10.0.0.0/24 unicast\n",
	}}
	service := newDaemonService(&Runtime{Config: appConfig}, state, config, time.Second)
	service.birdClientFactory = func(socketPath string, timeout time.Duration) birdClient {
		if socketPath != "/run/higgs/bird-higgstesth2.ctl" {
			t.Fatalf("socketPath = %q, want /run/higgs/bird-higgstesth2.ctl", socketPath)
		}
		return client
	}

	response := controlRequestViaPipe(t, service, controlRequest{Method: "bird_dump", NetNS: "higgstesth2", Command: "show route all"})
	if !response.OK || response.BirdDump == nil {
		t.Fatalf("bird_dump response = %#v", response)
	}
	inst := response.BirdDump.Instances["higgstesth2"]
	if inst.ControlSocket != "/run/higgs/bird-higgstesth2.ctl" || inst.Raw["show route all"] == "" {
		t.Fatalf("bird_dump instance = %#v", inst)
	}
	if len(client.rawCommands) != 1 || client.rawCommands[0] != "show route all" {
		t.Fatalf("raw commands = %#v, want show route all", client.rawCommands)
	}
}

func TestDaemonControlLinksStatusUsesReconcileSnapshot(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.LinkInstances = map[string]linkInstanceState{
		"link-1": {
			ID:            "link-1",
			GroupID:       "main",
			PeerZone:      "node-b.catofes.",
			TransportKind: "ipsec",
			LinkID:        "stable-link",
			TransportID:   "runtime-r3",
			ActualState:   "up",
			InterfaceName: "hgsabc123",
			XFRMIfID:      42,
			IKEName:       "runtime-r3",
			ChildSAName:   "runtime-r3-child",
			Endpoint:      "198.51.100.2:4500",
		},
	}
	state.IPsecReconcile = &ipsecReconcileState{
		LastRunUnix:  1234,
		DesiredLinks: 1,
		Desired: []desiredLinkState{{
			InstanceID:      "link-1",
			GroupID:         "main",
			PeerZone:        "node-b.catofes.",
			LinkID:          "stable-link",
			TransportID:     "runtime-r3",
			DesiredSpecHash: "desired-hash",
			InterfaceName:   "hgsabc123",
			XFRMIfID:        42,
			Endpoint:        "203.0.113.9:33403",
			LocalTunnelAddr: "fd00::1%hgsabc123",
			PeerTunnelAddr:  "fd00::2%hgsabc123",
		}},
		ActualSAs: []linkSAState{{
			Name:           "runtime-r3",
			ChildSA:        "runtime-r3-child",
			RemoteEndpoint: "203.0.113.9:33403",
			Established:    true,
		}},
	}
	service := newDaemonService(&Runtime{Config: defaultAppConfig()}, state, config, time.Second)

	response := controlRequestViaPipe(t, service, controlRequest{Method: "links_status"})
	if !response.OK || response.Links == nil {
		t.Fatalf("links_status response = %#v", response)
	}
	if response.Links.DesiredPlanSource != "last_reconcile" || response.Links.ReplannedDesired != 1 {
		t.Fatalf("links_status source/count = %q/%d, want last_reconcile/1", response.Links.DesiredPlanSource, response.Links.ReplannedDesired)
	}
	if len(response.Links.ActualSAs) != 1 {
		t.Fatalf("links_status actual_sas = %d, want 1", len(response.Links.ActualSAs))
	}
	links := response.Links.Inspection.Links
	if len(links) != 1 || links[0].Desired == nil {
		t.Fatalf("links_status links = %+v, want desired snapshot", links)
	}
	if got := links[0].Desired.Endpoint; got != "203.0.113.9:33403" {
		t.Fatalf("links_status desired endpoint = %q, want reconcile snapshot endpoint", got)
	}
}

func TestDaemonControlReadMethodsUseCommittedSnapshotWhileLiveStateLocked(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.LinkInstances = map[string]linkInstanceState{
		"link-committed": {
			ID:          "link-committed",
			GroupID:     "main",
			PeerZone:    "node-b.catofes.",
			ActualState: "up",
		},
	}
	state.IPsecReconcile = &ipsecReconcileState{
		LastRunUnix:  1234,
		DesiredLinks: 1,
		Desired: []desiredLinkState{{
			InstanceID: "link-committed",
			GroupID:    "main",
			PeerZone:   "node-b.catofes.",
			Endpoint:   "203.0.113.9:4500",
		}},
	}
	state.SyncPeers = map[string]syncPeerState{
		"node-b": {LastSyncUnix: 1111, ObservedAddr: "198.51.100.2:7777", ObservedUntilUnix: time.Now().Add(time.Minute).Unix()},
	}
	service := newDaemonService(&Runtime{Config: defaultAppConfig()}, state, config, time.Second)
	committedRev := service.StateStore.Meta().Revision

	state.Lock()
	state.LinkInstances["link-uncommitted"] = linkInstanceState{ID: "link-uncommitted"}
	state.IPsecReconcile.DesiredLinks = 99
	defer state.Unlock()

	status := controlRequestViaPipe(t, service, controlRequest{Method: "status"})
	if !status.OK {
		t.Fatalf("status response = %#v", status)
	}
	if status.StateRevision != committedRev || status.LinkInstances != 1 || status.DesiredLinks != 1 {
		t.Fatalf("status = %#v, want committed rev=%d link_instances=1 desired_links=1", status, committedRev)
	}

	links := controlRequestViaPipe(t, service, controlRequest{Method: "links_status"})
	if !links.OK || links.Links == nil {
		t.Fatalf("links_status response = %#v", links)
	}
	if links.StateRevision != committedRev || links.Links.ReplannedDesired != 1 {
		t.Fatalf("links_status = %#v, want committed rev=%d desired=1", links, committedRev)
	}

	peers := controlRequestViaPipe(t, service, controlRequest{Method: "peers_status"})
	if !peers.OK {
		t.Fatalf("peers_status response = %#v", peers)
	}
	if peers.StateRevision != committedRev {
		t.Fatalf("peers_status revision = %d, want %d", peers.StateRevision, committedRev)
	}
}

func TestDaemonPacketEventDoesNotWaitForLiveStateLock(t *testing.T) {
	state, config := buildTestNetworkState(t)
	service := newDaemonService(&Runtime{Config: defaultAppConfig()}, state, config, time.Second)
	packet := &gossip.Packet{
		Addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 33434},
		Message: &gossip.Message{
			Type:   gossip.MessagePong,
			PeerID: "node-b.catofes.",
			Pong:   &gossip.Pong{},
		},
	}

	state.Lock()
	done := make(chan daemonEventResult, 1)
	go func() {
		result, _, _ := service.handleEvent(daemonEvent{Type: daemonEventPacket, Packet: packet, Context: context.Background()})
		done <- result
	}()

	select {
	case result := <-done:
		if result.Error != nil {
			t.Fatalf("packet event error: %v", result.Error)
		}
	case <-time.After(time.Second):
		state.Unlock()
		t.Fatal("packet event blocked behind live state lock")
	}
	state.Unlock()

	snapshot, _ := service.StateStore.Snapshot()
	peerState := snapshot.SyncPeers["node-b.catofes."]
	if peerState.ObservedAddr != "198.51.100.9:33434" {
		t.Fatalf("observed addr = %q, want packet source", peerState.ObservedAddr)
	}
}

func TestDaemonControlRecordGet(t *testing.T) {
	state, config := buildTestNetworkState(t)
	record, err := buildSignedRecordAt(state, "node-b.catofes.", "site/name", []byte(`{"name":"node-b"}`), "policy.json", time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("buildSignedRecordAt: %v", err)
	}
	if err := state.Network.Put(record); err != nil {
		t.Fatalf("Put(record): %v", err)
	}
	record, err = buildSignedRecordAt(state, "node-b.catofes.", "site/name", []byte(`{"name":"node-b-2"}`), "policy.json", time.Unix(1001, 0))
	if err != nil {
		t.Fatalf("buildSignedRecordAt(second): %v", err)
	}
	if err := state.Network.Put(record); err != nil {
		t.Fatalf("Put(second record): %v", err)
	}
	service := newDaemonService(&Runtime{Config: defaultAppConfig()}, state, config, time.Second)

	response := controlRequestViaPipe(t, service, controlRequest{
		Method:  "record_get",
		Zone:    "node-b.catofes.",
		Key:     "site/name",
		History: 1,
	})
	if !response.OK {
		t.Fatalf("record_get response = %#v", response)
	}
	if response.Record.Key != "site/name" || response.Record.Value != `{"name":"node-b-2"}` || response.Record.RecordHash == "" {
		t.Fatalf("record_get record = %#v", response.Record)
	}
	history := response.Record.RecordHistory
	if len(history) != 1 {
		t.Fatalf("record_get history len = %d, want 1", len(history))
	}
	if item := history[0]; item.Value != `{"name":"node-b"}` {
		t.Fatalf("record_get history = %#v", history)
	}

	response = controlRequestViaPipe(t, service, controlRequest{
		Method: "record_get",
		Zone:   "node-b.catofes.",
		Key:    "missing",
	})
	if response.OK || response.Error == "" {
		t.Fatalf("missing record_get response = %#v, want error", response)
	}
}
