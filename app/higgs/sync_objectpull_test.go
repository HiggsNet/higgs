package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

// TestSyncRoundFallsBackToObjectPull verifies that when a zone record exceeds
// the UDP datagram budget, syncRound still converges via TCP object pull.
func TestSyncRoundFallsBackToObjectPull(t *testing.T) {
	now := time.Unix(1000, 0)

	// Build a shared network state (both A and B start with the same base).
	stateBase, _ := buildTestNetworkState(t)
	stateBase.Network.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)

	// A writes a large record under node-b.catofes. (zone private key is node-b's).
	largeValue := make([]byte, 3000)
	for i := range largeValue {
		largeValue[i] = byte(i % 256)
	}
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "bigdata",
		Type:      "test.data",
		Value:     largeValue,
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, stateBase.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := stateBase.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}

	// A state/config.
	stateA := cloneStateFile(stateBase)
	configA := &syncConfigFile{
		PeerID:          "node-a.catofes.",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: gossip.DefaultDatagramBudget,
	}

	// Start A's UDP transport first so we know its bound address.
	transportA, err := gossip.Listen(gossip.Config{
		PeerID:          configA.PeerID,
		ListenAddr:      configA.ListenAddr,
		MaxMessageBytes: gossip.DefaultDatagramBudget,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(A): %v", err)
	}
	defer transportA.Close()

	// Derive TCP object-pull address from the actual UDP bind address.
	tcpAddrA := objectPullTCPAddr(transportA.LocalAddr().String())
	listenerA, err := objectPullTCPServe(tcpAddrA, objectPullLookup(func() *stateFile { return stateA }))
	if err != nil {
		t.Fatalf("objectPullTCPServe(A): %v", err)
	}
	if listenerA != nil {
		defer listenerA.Close()
	}

	// B state/config (defined after transportA so bootstrap can use its address).
	stateB := cloneStateFile(stateBase)
	// Remove the large record from B so it has to pull it.
	delete(stateB.Network.Zones["node-b.catofes."].Records, "bigdata")
	configB := &syncConfigFile{
		PeerID:          "node-b.catofes.",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: gossip.DefaultDatagramBudget,
		Bootstrap: []syncConfigPeer{
			{ID: configA.PeerID, Addr: transportA.LocalAddr().String()},
		},
	}

	// Start B's UDP transport.
	transportB, err := gossip.Listen(gossip.Config{
		PeerID:          configB.PeerID,
		ListenAddr:      configB.ListenAddr,
		MaxMessageBytes: gossip.DefaultDatagramBudget,
		KnownPeers: map[string]*net.UDPAddr{
			configA.PeerID: transportA.LocalAddr(),
		},
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(B): %v", err)
	}
	defer transportB.Close()

	// A runs sync serve in background.
	srA := newSyncRuntime(stateA, configA, transportA, &Runtime{Clock: time.Now})
	srA.addVerifiedZonePeers()
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	go func() {
		for {
			select {
			case <-ctxA.Done():
				return
			default:
			}
			packet, err := receiveWithContext(ctxA, transportA, time.Now().Add(time.Second))
			if err != nil {
				continue
			}
			stateA.Lock()
			_ = srA.handlePacket(packet)
			stateA.Unlock()
		}
	}()

	// B runs sync round against A.
	statePathB := t.TempDir() + "/b.db"
	srB := newSyncRuntime(stateB, configB, transportB, &Runtime{Clock: time.Now, StatePath: statePathB})
	if err := srB.syncRound(context.Background(), configA.PeerID, 5*time.Second); err != nil {
		t.Fatalf("syncRound(B->A): %v", err)
	}

	// Verify B now has the large record via object pull.
	zs := stateB.Network.Zones["node-b.catofes."]
	if zs == nil {
		t.Fatalf("zone node-b.catofes. missing on B")
	}
	got := zs.Records["bigdata"]
	if got == nil {
		t.Fatalf("record 'bigdata' missing on B")
	}
	if len(got.Value) != 3000 {
		t.Fatalf("record value len = %d, want 3000", len(got.Value))
	}
}

func TestSyncRoundReportsUnreachableObjectPull(t *testing.T) {
	now := time.Unix(1000, 0)

	stateBase, _ := buildTestNetworkState(t)
	stateBase.Network.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)

	largeValue := make([]byte, 3000)
	for i := range largeValue {
		largeValue[i] = byte(i % 256)
	}
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "bigdata",
		Type:      "test.data",
		Value:     largeValue,
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, stateBase.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := stateBase.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}

	stateA := cloneStateFile(stateBase)
	configA := &syncConfigFile{
		PeerID:          "node-a.catofes.",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: gossip.DefaultDatagramBudget,
	}
	transportA, err := gossip.Listen(gossip.Config{
		PeerID:          configA.PeerID,
		ListenAddr:      configA.ListenAddr,
		MaxMessageBytes: gossip.DefaultDatagramBudget,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(A): %v", err)
	}
	defer transportA.Close()

	stateB := cloneStateFile(stateBase)
	delete(stateB.Network.Zones["node-b.catofes."].Records, "bigdata")
	configB := &syncConfigFile{
		PeerID:          "node-b.catofes.",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: gossip.DefaultDatagramBudget,
		Bootstrap: []syncConfigPeer{
			{ID: configA.PeerID, Addr: transportA.LocalAddr().String()},
		},
	}
	transportB, err := gossip.Listen(gossip.Config{
		PeerID:          configB.PeerID,
		ListenAddr:      configB.ListenAddr,
		MaxMessageBytes: gossip.DefaultDatagramBudget,
		KnownPeers: map[string]*net.UDPAddr{
			configA.PeerID: transportA.LocalAddr(),
		},
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(B): %v", err)
	}
	defer transportB.Close()

	srA := newSyncRuntime(stateA, configA, transportA, &Runtime{Clock: time.Now})
	srA.addVerifiedZonePeers()
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	go func() {
		for {
			select {
			case <-ctxA.Done():
				return
			default:
			}
			packet, err := receiveWithContext(ctxA, transportA, time.Now().Add(time.Second))
			if err != nil {
				continue
			}
			stateA.Lock()
			_ = srA.handlePacket(packet)
			stateA.Unlock()
		}
	}()

	statePathB := t.TempDir() + "/b.db"
	srB := newSyncRuntime(stateB, configB, transportB, &Runtime{Clock: time.Now, StatePath: statePathB})
	err = srB.syncRound(context.Background(), configA.PeerID, 3*time.Second)
	if err != nil {
		t.Fatalf("syncRound with UDP chunk fallback: %v", err)
	}
	if got := stateB.Network.Zones["node-b.catofes."].Records["bigdata"]; got != nil {
		if !bytes.Equal(got.Value, largeValue) {
			t.Fatalf("large record value length = %d, want %d", len(got.Value), len(largeValue))
		}
	} else {
		t.Fatalf("large record did not sync via UDP chunk fallback")
	}
	stats := stateB.SyncPeers[configA.PeerID].ObjectPullStats
	if stats == nil {
		t.Fatalf("object pull stats missing")
	}
	if stats.LargeObjectUnreachable == 0 {
		t.Fatalf("unreachable stats = %#v", stats)
	}
	if stats.Failures == 0 {
		t.Fatalf("failure stats = %#v", stats)
	}
	datagramStats := stateB.SyncPeers[configA.PeerID].DatagramStats
	if datagramStats == nil || datagramStats.ChunkFallbacks == 0 {
		t.Fatalf("chunk fallback stats = %#v", datagramStats)
	}
}

func cloneStateFile(s *stateFile) *stateFile {
	if s == nil {
		return nil
	}
	data, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	var out stateFile
	if err := json.Unmarshal(data, &out); err != nil {
		panic(err)
	}
	return &out
}
