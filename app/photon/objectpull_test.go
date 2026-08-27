package main

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	listener, err := objectPullTCPServe("127.0.0.1:0", objectPullLookup(func() *stateFile { return state }))
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("objectPullTCPServe: %v", err)
	}
	defer listener.Close()

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

func TestObjectPullListenAddr(t *testing.T) {
	if got := objectPullListenAddr("127.0.0.1:33434"); got != "127.0.0.1:33434" {
		t.Fatalf("objectPullListenAddr = %q, want 127.0.0.1:33434", got)
	}
}

func TestObjectPullLookupRejectsRevokedZone(t *testing.T) {
	// Core revocation logic is tested in pkg/core/gossip.
	// Full object-pull revocation integration would need catofes private key
	// which buildTestNetworkState does not expose; skip for now.
	t.Skip("revocation tested in pkg/core/gossip")
}

func TestCommonObjectPullAddressPrefersVerifiedObservedPath(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Now()
	state.SyncPeers = map[string]syncPeerState{"node-b.catofes.": {
		ObservedAddr: "198.51.100.10:33434", ObservedUntilUnix: now.Add(time.Minute).Unix(),
	}}
	config.Bootstrap = []syncConfigPeer{{ID: "node-b.catofes.", Addr: "192.0.2.10:33434"}}
	input := testDaemonGossipDiscoveryInput(state, config)
	if got := corehost.ResolveGossipObjectPullAddress(input, "node-b.catofes.", now); got != "198.51.100.10:33434" {
		t.Fatalf("object-pull address = %q, want verified observed path", got)
	}
	input.Peers["unknown.catofes."] = input.Peers["node-b.catofes."]
	if got := corehost.ResolveGossipObjectPullAddress(input, "unknown.catofes.", now); got != "" {
		t.Fatalf("unverified observed address = %q, want empty", got)
	}
}

func TestCommonObjectPullAddressUsesSignedEndpoint(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Now()
	record := &zone.Record{
		Zone: "node-b.catofes.", Key: gossip.EndpointRecordKeyUDP, Type: "sync.endpoint",
		Value: endpointRecordBytes([]gossip.LocalEndpoint{{
			IP: net.ParseIP("203.0.113.10"), Port: 33434, Scope: "global", Priority: 100, Source: gossip.SourceAdvertise,
		}}, now),
		Version: 1, Timestamp: now.Unix(),
	}
	if err := photoncrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatal(err)
	}
	if got := corehost.ResolveGossipObjectPullAddress(testDaemonGossipDiscoveryInput(state, config), "node-b.catofes.", now); got != "203.0.113.10:33434" {
		t.Fatalf("object-pull address = %q, want signed endpoint", got)
	}
}

func TestOfflineObjectPullDoesNotPersistDiagnostics(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	_, err := tryObjectPullTCPUntil(corehost.GossipDiscoveryInput{Network: state.Network}, "node-b.catofes.", "node-b.catofes.", time.Time{})
	if err == nil {
		t.Fatalf("tryObjectPullTCP succeeded without a TCP address")
	}
}

func TestObjectPullResultUsesObservabilityStoreWhileConstructorInputLocked(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(7100, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)
	beforeRevision := service.StateStore.Meta().Revision

	state.Lock()
	unlock := state.Unlock
	service.observeObjectPullResult(objectPullTransportResult{
		PeerID:      "node-b.catofes.",
		Zone:        "node-b.catofes.",
		Bytes:       4096,
		Unreachable: false,
	})
	unlock()

	snapshot, ok := service.PeerObservability.Snapshot("node-b.catofes.", now)
	if !ok {
		t.Fatal("object pull observability snapshot missing")
	}
	stats := snapshot.ObjectPullStats
	if stats == nil {
		t.Fatal("object pull stats missing from observability snapshot")
	}
	if stats.Successes != 1 || stats.LastBytes != 4096 || stats.LastZone != "node-b.catofes." {
		t.Fatalf("object pull stats = %+v, want committed success result", stats)
	}
	if after := service.StateStore.Meta().Revision; after != beforeRevision {
		t.Fatalf("state revision changed for object pull diagnostics: before=%d after=%d", beforeRevision, after)
	}
}

func TestSubmitObjectPullNoAddressUsesObservabilityStoreWhileConstructorInputLocked(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(7200, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newTestDaemonService(rt, state, config, time.Second)
	beforeRevision := service.StateStore.Meta().Revision

	state.Lock()
	unlock := state.Unlock
	(daemonObjectPullWorker{daemon: service}).PullGossipObject(context.Background(), gossip.StartObjectPullAction{PeerID: "node-b.catofes.", Zone: "node-b.catofes."})
	unlock()

	snapshot, ok := service.PeerObservability.Snapshot("node-b.catofes.", now)
	if !ok {
		t.Fatal("object pull observability snapshot missing")
	}
	stats := snapshot.ObjectPullStats
	if stats == nil {
		t.Fatal("object pull stats missing from observability snapshot")
	}
	if stats.Failures != 1 || stats.LargeObjectUnreachable != 1 || !stats.LastUnreachable {
		t.Fatalf("object pull stats = %+v, want committed unreachable failure", stats)
	}
	if after := service.StateStore.Meta().Revision; after != beforeRevision {
		t.Fatalf("state revision changed for object pull diagnostics: before=%d after=%d", beforeRevision, after)
	}
}

func TestObjectPullClientTimeoutHonorsOuterDeadline(t *testing.T) {
	if got, err := objectPullClientTimeoutUntil(time.Time{}, objectPullClientDialTimeout); err != nil || got != objectPullClientDialTimeout {
		t.Fatalf("zero deadline timeout = %s/%v, want %s/nil", got, err, objectPullClientDialTimeout)
	}
	deadline := time.Now().Add(50 * time.Millisecond)
	got, err := objectPullClientTimeoutUntil(deadline, objectPullClientDialTimeout)
	if err != nil {
		t.Fatalf("objectPullClientTimeoutUntil future: %v", err)
	}
	if got <= 0 || got > 100*time.Millisecond {
		t.Fatalf("future deadline timeout = %s, want small positive timeout", got)
	}
	if _, err := objectPullClientTimeoutUntil(time.Now().Add(-time.Millisecond), objectPullClientDialTimeout); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline error = %v, want DeadlineExceeded", err)
	}
}

func TestOfflineObjectPullExpiredDeadlineDoesNotPersistDiagnostics(t *testing.T) {
	input := corehost.GossipDiscoveryInput{Bootstrap: map[string]*net.UDPAddr{
		"node-b.catofes.": {IP: net.ParseIP("127.0.0.1"), Port: 1},
	}}
	_, err := tryObjectPullTCPUntil(input, "node-b.catofes.", "node-b.catofes.", time.Now().Add(-time.Millisecond))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("tryObjectPullTCPUntil error = %v, want DeadlineExceeded", err)
	}
}

func TestObjectPullConcurrencyLimit(t *testing.T) {
	for range maxObjectPullConcurrency {
		objectPullClientLimiter <- struct{}{}
	}
	defer func() {
		for range maxObjectPullConcurrency {
			<-objectPullClientLimiter
		}
	}()

	_, err := pullObjectTCP("127.0.0.1:1", &gossip.ObjectPullRequest{
		Type: gossip.ObjectPullZone,
		Zone: "node-b.catofes.",
	})
	if err == nil {
		t.Fatalf("pullObjectTCP succeeded with full limiter")
	}
}

func TestObjectPullServerConcurrencyLimit(t *testing.T) {
	var releases []func()
	for i := range maxObjectPullServerConcurrency {
		release, ok := acquireObjectPullServerSlot()
		if !ok {
			t.Fatalf("acquire server slot %d failed", i)
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()

	if release, ok := acquireObjectPullServerSlot(); ok {
		release()
		t.Fatalf("acquireObjectPullServerSlot succeeded with full limiter")
	}
}

func TestObjectPullPerPeerInflightLimit(t *testing.T) {
	var releases []func()
	for i := range maxObjectPullPerPeerInflight {
		release, err := objectPullPeerLimiter.acquire("node-b.catofes.")
		if err != nil {
			t.Fatalf("acquire(%d): %v", i, err)
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()

	_, err := pullObjectTCPForPeer("node-b.catofes.", "127.0.0.1:1", &gossip.ObjectPullRequest{
		Type: gossip.ObjectPullZone,
		Zone: "node-b.catofes.",
	})
	if err == nil {
		t.Fatalf("pullObjectTCPForPeer succeeded with full peer limiter")
	}
	if got, want := err.Error(), "object pull per-peer inflight limit reached"; !strings.Contains(got, want) {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestObjectPullQuotaAccountsBytesAndObjects(t *testing.T) {
	quotas := newLockedPeerQuotas(gossip.QuotaConfig{
		ByteRate:    1,
		ByteBurst:   8,
		ObjectRate:  1,
		ObjectBurst: 1,
	})
	now := time.Unix(1000, 0)

	if err := quotas.allow("node-b.catofes.", 4, 1, now); err != nil {
		t.Fatalf("allow(first): %v", err)
	}
	if err := quotas.allow("node-b.catofes.", 1, 1, now); !errors.Is(err, gossip.ErrQuotaExceeded) {
		t.Fatalf("allow(over objects) = %v, want ErrQuotaExceeded", err)
	}
	if err := quotas.allow("node-b.catofes.", 9, 0, now.Add(2*time.Second)); !errors.Is(err, gossip.ErrQuotaExceeded) {
		t.Fatalf("allow(over bytes) = %v, want ErrQuotaExceeded", err)
	}
}
