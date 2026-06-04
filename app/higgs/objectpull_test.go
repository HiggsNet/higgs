package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func TestObjectPullTCPServerClient(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
	now := time.Unix(1000, 0)
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "identity",
		Type:      "node.identity",
		Value:     []byte("node-a"),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
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

func TestResolvePeerTCPAddrPrefersBootstrap(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	config := &syncConfigFile{
		Bootstrap: []syncConfigPeer{
			{ID: "node-b", Addr: "192.0.2.10:33434"},
		},
	}
	if got := resolvePeerTCPAddr(state, config, "node-b"); got != "192.0.2.10:33434" {
		t.Fatalf("resolvePeerTCPAddr = %q, want 192.0.2.10:33434", got)
	}
	if got := resolvePeerTCPAddr(state, config, "unknown"); got != "" {
		t.Fatalf("resolvePeerTCPAddr unknown = %q, want empty", got)
	}
}

func TestResolvePeerTCPAddrUsesSignedEndpoint(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.Network.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
	now := time.Now()
	endpoints := []gossip.LocalEndpoint{
		{IP: net.ParseIP("203.0.113.10"), Port: 33434, Scope: "global", Priority: 100, Source: gossip.SourceAdvertise},
	}
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     gossip.EndpointRecordBytes(endpoints, now),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord(endpoint): %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt(endpoint): %v", err)
	}

	if got := resolvePeerTCPAddr(state, &syncConfigFile{}, "node-b.catofes."); got != "203.0.113.10:33434" {
		t.Fatalf("resolvePeerTCPAddr signed endpoint = %q, want 203.0.113.10:33434", got)
	}
}

func TestResolvePeerTCPAddrUsesVerifiedObservedPath(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Now()
	state.SyncPeers = make(map[string]syncPeerState)
	state.SyncPeers["node-b.catofes."] = syncPeerState{
		ObservedAddr:          "127.0.0.1:33434",
		ObservedFirstSeenUnix: now.Unix(),
		ObservedLastSeenUnix:  now.Unix(),
		ObservedUntilUnix:     now.Add(time.Minute).Unix(),
		ObservedSource:        string(gossip.MessagePing),
	}

	if got := resolvePeerTCPAddr(state, &syncConfigFile{}, "node-b.catofes."); got != "127.0.0.1:33434" {
		t.Fatalf("resolvePeerTCPAddr observed = %q, want 127.0.0.1:33434", got)
	}

	state.SyncPeers["unknown.catofes."] = syncPeerState{
		ObservedAddr:          "127.0.0.1:33435",
		ObservedFirstSeenUnix: now.Unix(),
		ObservedLastSeenUnix:  now.Unix(),
		ObservedUntilUnix:     now.Add(time.Minute).Unix(),
		ObservedSource:        string(gossip.MessagePing),
	}
	if got := resolvePeerTCPAddr(state, &syncConfigFile{}, "unknown.catofes."); got != "" {
		t.Fatalf("resolvePeerTCPAddr unverified observed = %q, want empty", got)
	}
}

func TestResolvePeerTCPAddrPrefersObservedOverPrivateSignedEndpoint(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Now()
	endpoints := []gossip.LocalEndpoint{
		{IP: net.ParseIP("10.16.255.8"), Port: 33435, Scope: "global", Priority: 100, Source: gossip.SourceInterface},
	}
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       gossip.EndpointRecordKeyUDP,
		Type:      "sync.endpoint",
		Value:     gossip.EndpointRecordBytes(endpoints, now),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		t.Fatalf("SignRecord(endpoint): %v", err)
	}
	if err := state.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt(endpoint): %v", err)
	}
	state.SyncPeers = map[string]syncPeerState{
		"node-b.catofes.": {
			ObservedAddr:          "114.246.101.91:33435",
			ObservedFirstSeenUnix: now.Unix(),
			ObservedLastSeenUnix:  now.Unix(),
			ObservedUntilUnix:     now.Add(time.Minute).Unix(),
			ObservedSource:        string(gossip.MessagePing),
		},
	}

	if got := resolvePeerTCPAddr(state, &syncConfigFile{}, "node-b.catofes."); got != "114.246.101.91:33435" {
		t.Fatalf("resolvePeerTCPAddr = %q, want observed public path", got)
	}
}

func TestObjectPullRecordsUnreachablePeer(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	_, err := tryObjectPullTCP(state, &syncConfigFile{}, "node-b.catofes.", "node-b.catofes.")
	if err == nil {
		t.Fatalf("tryObjectPullTCP succeeded without a TCP address")
	}
	stats := state.SyncPeers["node-b.catofes."].ObjectPullStats
	if stats == nil {
		t.Fatalf("object pull stats missing")
	}
	if stats.LargeObjectUnreachable != 1 || !stats.LastUnreachable {
		t.Fatalf("unreachable stats = %#v", stats)
	}
	if stats.LastObject != "zone" || stats.LastZone != "node-b.catofes." || stats.LastError == "" {
		t.Fatalf("last object stats = %#v", stats)
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

func TestObjectPullExpiredDeadlineRecordsUnreachable(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	config := &syncConfigFile{
		Bootstrap: []syncConfigPeer{
			{ID: "node-b.catofes.", Addr: "127.0.0.1:1"},
		},
	}

	_, err := tryObjectPullTCPUntil(state, config, "node-b.catofes.", "node-b.catofes.", time.Now().Add(-time.Millisecond))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("tryObjectPullTCPUntil error = %v, want DeadlineExceeded", err)
	}
	stats := state.SyncPeers["node-b.catofes."].ObjectPullStats
	if stats == nil || stats.LargeObjectUnreachable != 1 || !stats.LastUnreachable {
		t.Fatalf("deadline unreachable stats = %#v", stats)
	}
}

func TestObjectPullConcurrencyLimit(t *testing.T) {
	for i := 0; i < maxObjectPullConcurrency; i++ {
		objectPullClientLimiter <- struct{}{}
	}
	defer func() {
		for i := 0; i < maxObjectPullConcurrency; i++ {
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
	for i := 0; i < maxObjectPullServerConcurrency; i++ {
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
	for i := 0; i < maxObjectPullPerPeerInflight; i++ {
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
