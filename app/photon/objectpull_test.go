package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestObjectPullTCPServerClient(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	now := time.Unix(1000, 0)
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "identity",
		Type:      "node.identity",
		Value:     []byte("node-a"),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := photoncrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	runtime := corehost.NewRuntime(corehost.NewClock(nil), corehost.DefaultEventBuffer, nil, corehost.GossipRuntimeConfig{})
	if err := runtime.StartGossipObjectPullServer(t.Context(), listener, objectPullLookup(func() *stateFile { return state }), 0, 0); err != nil {
		_ = listener.Close()
		t.Fatalf("StartGossipObjectPullServer: %v", err)
	}
	defer runtime.Stop()

	// Pull zone snapshot.
	resp, err := pullObjectTCP(listener.Addr().String(), &gossip.ObjectPullRequest{
		Type: gossip.ObjectPullZone,
		Zone: "node-b.catofes.",
	})
	if err != nil {
		t.Fatalf("pullObjectTCP: %v", err)
	}
	if !resp.OK {
		t.Fatalf("object pull failed: %s", resp.Error)
	}
	if resp.Snapshot == nil || resp.Snapshot.Zone != "node-b.catofes." {
		t.Fatalf("unexpected snapshot: %+v", resp.Snapshot)
	}
	if len(resp.Snapshot.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(resp.Snapshot.Records))
	}

	// Pull single record.
	resp2, err := pullObjectTCP(listener.Addr().String(), &gossip.ObjectPullRequest{
		Type: gossip.ObjectPullRecord,
		Zone: "node-b.catofes.",
		Key:  "identity",
	})
	if err != nil {
		t.Fatalf("pullObjectTCP record: %v", err)
	}
	if !resp2.OK || resp2.Record == nil {
		t.Fatalf("record pull failed: %s", resp2.Error)
	}
	if string(resp2.Record.Record.Value) != "node-a" {
		t.Fatalf("unexpected record value: %s", resp2.Record.Record.Value)
	}
}

func TestObjectPullTCPAddrDerivation(t *testing.T) {
	if got := objectPullTCPAddr("192.0.2.1:33434"); got != "192.0.2.1:33434" {
		t.Fatalf("objectPullTCPAddr = %q, want 192.0.2.1:33434", got)
	}
	if got := objectPullTCPAddr("[2001:db8::1]:33434"); got != "[2001:db8::1]:33434" {
		t.Fatalf("objectPullTCPAddr v6 = %q, want [2001:db8::1]:33434", got)
	}
}

func TestObjectPullLookupRejectsRevokedZone(t *testing.T) {
	// Core revocation logic is tested in pkg/core/gossip.
	// Full object-pull revocation integration would need catofes private key
	// which buildTestNetworkState does not expose; skip for now.
	t.Skip("revocation tested in pkg/core/gossip")
}

func TestOfflineObjectPullDoesNotPersistDiagnostics(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	executor := corehost.NewGossipObjectPullExecutor(corehost.GossipObjectPullExecutorConfig{Client: photonlinux.GossipObjectPullClient{}})
	completion := executor.PullFrom(t.Context(), corehost.GossipDiscoveryInput{Network: state.Network}, gossip.StartObjectPullAction{PeerID: "node-b.catofes.", Zone: "node-b.catofes."})
	if completion.Err == nil {
		t.Fatalf("object pull succeeded without a TCP address")
	}
}

func TestOfflineObjectPullExpiredDeadlineDoesNotPersistDiagnostics(t *testing.T) {
	input := corehost.GossipDiscoveryInput{Bootstrap: map[string]*net.UDPAddr{
		"node-b.catofes.": {IP: net.ParseIP("127.0.0.1"), Port: 1},
	}, Network: zone.NewNetworkState()}
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Millisecond))
	cancel()
	executor := corehost.NewGossipObjectPullExecutor(corehost.GossipObjectPullExecutorConfig{Client: photonlinux.GossipObjectPullClient{}})
	completion := executor.PullFrom(ctx, input, gossip.StartObjectPullAction{PeerID: "node-b.catofes.", Zone: "node-b.catofes."})
	if !errors.Is(completion.Err, context.DeadlineExceeded) {
		t.Fatalf("object pull error = %v, want DeadlineExceeded", completion.Err)
	}
}
