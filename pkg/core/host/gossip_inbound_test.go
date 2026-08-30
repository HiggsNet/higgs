package host

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

type memoryInboundController struct {
	budget        int
	outbound      []gossip.OutboundMessage
	issues        []GossipExecutionIssue
	controllerErr error
}

func (controller *memoryInboundController) GossipDatagramBudget() int { return controller.budget }

func (controller *memoryInboundController) SendGossip(_ context.Context, outbound gossip.OutboundMessage) error {
	controller.outbound = append(controller.outbound, outbound)
	return controller.controllerErr
}

func TestRuntimeInboundOwnsObservedCheckpointAndAddressBookPublication(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	path := zone.ZonePath("catofes.")
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	peerPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rootAuthority := &zone.ZoneAuthority{Zone: zone.RootZone, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{
		Key: rootPublic, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermDelegate}}},
	}}}
	peerAuthority := &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: peerPublic}}}
	delegation := &zone.Delegation{ZoneName: path, Scope: zone.DelegationScopeDirectChild, Authority: *peerAuthority}
	if err := photoncrypto.SignDelegation(delegation, zone.RootZone, rootPrivate); err != nil {
		t.Fatal(err)
	}
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	network.Zones[zone.RootZone].Delegations[path] = delegation
	network.Zones[path] = zone.NewZoneState(path, peerAuthority)
	verified := &corestate.VerifiedState{ManagedZone: "local.catofes.", Network: network}
	initial := corestate.View{State: verified, Gossip: &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{}}}
	committed := corestate.View{State: verified, Gossip: &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
		path.String(): {ObservedEndpoint: "198.51.100.10:33434", ObservedUntilUnix: now.Add(time.Minute).Unix()},
	}}}
	state := &memoryGossipStateStore{views: []corestate.View{initial, committed, committed}}
	runtime := NewRuntime(newFakeClock(now), 2, state, GossipRuntimeConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer runtime.Stop()
	transport, _ := bindMemoryGossipTransport(t, runtime, path.String())
	packet := &gossip.Packet{
		Addr:    &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 33434},
		Message: &gossip.Message{Type: gossip.MessageFetchCatalogPage, PeerID: path.String(), FetchCatalogPage: &gossip.FetchCatalogPage{}},
	}
	if _, err := runtime.HandleGossipHostEvent(context.Background(), GossipPacketReceived{Packet: packet}, now, nil); err != nil {
		t.Fatal(err)
	}
	if len(state.updates) != 1 || !state.updates[0][path.String()].ObservedEndpoint.Set {
		t.Fatalf("checkpoint updates = %#v", state.updates)
	}
	if observed := transport.ObservedPeerAddr(path.String()); observed == nil || observed.String() != packet.Addr.String() {
		t.Fatalf("observed publication = %v", observed)
	}
	diagnostics, ok := runtime.Observability.Snapshot(path.String(), now)
	if !ok || diagnostics.ObservedSource != string(gossip.MessageFetchCatalogPage) {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestRuntimeExecuteGossipPacketActionsPlansPingResponsesAndHint(t *testing.T) {
	runtime := NewRuntime(newFakeClock(time.Unix(100, 0)), 2, &memoryGossipStateStore{views: []corestate.View{loadedGossipState("local.catofes.")}}, GossipRuntimeConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer runtime.Stop()
	controller := &memoryInboundController{}
	packet := &gossip.Packet{Message: &gossip.Message{
		Type:   gossip.MessagePing,
		PeerID: "peer-a",
		Ping:   &gossip.Ping{Summary: &corestate.CatalogSummary{CatalogRoot: []byte("remote"), ZoneCount: 1}},
	}}
	actions := runtime.Gossip.PlanInbound(packet)
	if err := runtime.executeGossipPacketActions(context.Background(), actions, controller, controller.budget); err != nil {
		t.Fatalf("executeGossipPacketActions: %v", err)
	}
	if len(controller.outbound) != 2 || controller.outbound[0].Message.Type != gossip.MessagePong || controller.outbound[1].Message.Type != gossip.MessageFetchCatalogPage {
		t.Fatalf("outbound = %#v, want PONG then FETCH_CATALOG_PAGE", controller.outbound)
	}
	diagnostics, ok := runtime.Observability.Snapshot("peer-a", time.Unix(100, 0))
	if !ok || diagnostics.DatagramStats == nil || diagnostics.DatagramStats.LastCatalogRootHex == "" || diagnostics.HintAccepted != 1 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestRuntimeExecuteGossipPacketActionsBuildsBoundedCatalogPage(t *testing.T) {
	runtime := NewRuntime(newFakeClock(time.Unix(100, 0)), 1, &memoryGossipStateStore{views: []corestate.View{loadedGossipState("a.catofes.", "b.catofes.")}}, GossipRuntimeConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer runtime.Stop()
	controller := &memoryInboundController{
		budget: gossip.DefaultDatagramBudget,
	}
	packet := &gossip.Packet{Message: &gossip.Message{
		Type:             gossip.MessageFetchCatalogPage,
		PeerID:           "peer-a",
		FetchCatalogPage: &gossip.FetchCatalogPage{},
	}}
	if err := runtime.executeGossipPacketActions(context.Background(), runtime.Gossip.PlanInbound(packet), controller, controller.budget); err != nil {
		t.Fatalf("executeGossipPacketActions: %v", err)
	}
	if len(controller.outbound) != 1 || controller.outbound[0].Message.CatalogPage == nil {
		t.Fatalf("outbound = %#v", controller.outbound)
	}
	if size := gossip.MessageWireSize(controller.outbound[0].Message); size > controller.budget {
		t.Fatalf("catalog page size = %d, limit %d", size, controller.budget)
	}
}

func TestRuntimeOwnsFetchZoneChunkSendAndNACKRepair(t *testing.T) {
	now := time.Unix(100, 0)
	view := loadedGossipState("remote.catofes.")
	view.State.Network.Zones["remote.catofes."].Records["large"] = &zone.Record{
		Zone: "remote.catofes.", Key: "large", Type: "test.data", Value: make([]byte, 3000), Version: 1,
	}
	runtime := NewRuntime(newFakeClock(now), 4, &memoryGossipStateStore{views: []corestate.View{view}}, GossipRuntimeConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()})
	defer runtime.Stop()
	controller := &memoryInboundController{budget: gossip.DefaultDatagramBudget}
	fetch := &gossip.Message{
		Type: gossip.MessageFetchZone, PeerID: "peer-a",
		FetchZone: &gossip.FetchZone{Zone: "remote.catofes.", ChunkFallback: true},
	}
	if err := runtime.executeGossipPacketActions(context.Background(), runtime.Gossip.PlanInbound(&gossip.Packet{Message: fetch}), controller, controller.budget); err != nil {
		t.Fatalf("execute FETCH_ZONE: %v", err)
	}
	diagnostics, ok := runtime.Observability.Snapshot("peer-a", now)
	if !ok || diagnostics.DatagramStats == nil || diagnostics.DatagramStats.ChunkFallbacks == 0 || diagnostics.LastResponderKind != "chunk_fallback" {
		t.Fatalf("fetch diagnostics = %#v", diagnostics)
	}
	var firstChunk *gossip.ObjectChunk
	for _, outbound := range controller.outbound {
		if outbound.Message != nil && outbound.Message.ObjectChunk != nil {
			firstChunk = outbound.Message.ObjectChunk
			break
		}
	}
	if firstChunk == nil {
		t.Fatalf("outbound = %#v, want object chunks", controller.outbound)
	}
	controller.outbound = nil
	nack := &gossip.Message{
		Type: gossip.MessageObjectChunkNACK, PeerID: "peer-a",
		ObjectChunkNACK: &gossip.ObjectChunkNACK{TransferID: append([]byte(nil), firstChunk.TransferID...), Missing: []uint16{firstChunk.Index}},
	}
	if err := runtime.executeGossipPacketActions(context.Background(), runtime.Gossip.PlanInbound(&gossip.Packet{Message: nack}), controller, controller.budget); err != nil {
		t.Fatalf("execute OBJECT_CHUNK_NACK: %v", err)
	}
	diagnostics, _ = runtime.Observability.Snapshot("peer-a", now)
	if diagnostics.DatagramStats.ChunkRepairNACKs != 1 || diagnostics.DatagramStats.ChunkRepairChunks != 1 {
		t.Fatalf("NACK diagnostics = %#v", diagnostics.DatagramStats)
	}
	if len(controller.outbound) != 1 || controller.outbound[0].Message.ObjectChunk == nil || controller.outbound[0].Message.ObjectChunk.Index != firstChunk.Index {
		t.Fatalf("repair outbound = %#v", controller.outbound)
	}
}

func TestRuntimeExecuteGossipPacketActionsRespondsToActivePingWhenQueueFull(t *testing.T) {
	controller := &memoryInboundController{}
	runtime := NewRuntime(newFakeClock(time.Unix(100, 0)), 1, &memoryGossipStateStore{views: []corestate.View{loadedGossipState()}}, gossipConfigCapturingIssues(GossipRuntimeConfig{PeerID: "local.catofes.", Limits: corestate.DefaultSyncLimits()}, &controller.issues))
	defer runtime.Stop()
	runtime.Gossip.NewSession("peer-a")
	if err := runtime.PostGossip(&gossip.SyncTimerEvent{PeerID: "occupy"}); err != nil {
		t.Fatalf("fill queue: %v", err)
	}
	packet := &gossip.Packet{Message: &gossip.Message{
		Type:   gossip.MessagePing,
		PeerID: "peer-a",
		Ping:   &gossip.Ping{Summary: &corestate.CatalogSummary{CatalogRoot: []byte("remote")}},
	}}
	if err := runtime.executeGossipPacketActions(context.Background(), runtime.Gossip.PlanInbound(packet), controller, controller.budget); err != nil {
		t.Fatalf("executeGossipPacketActions: %v", err)
	}
	if len(controller.outbound) == 0 || controller.outbound[0].Message.Type != gossip.MessagePong {
		t.Fatalf("outbound = %#v, want responder PONG", controller.outbound)
	}
	if len(controller.issues) != 1 || !errors.Is(controller.issues[0].Err, ErrEventQueueFull) {
		t.Fatalf("issues = %#v, want queue-full report", controller.issues)
	}
}
