package gossip

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func TestMarshalUnmarshalPing(t *testing.T) {
	message := &Message{
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     1,
		Timestamp: 123,
		Ping: &Ping{Zones: []ZoneDigest{{
			Zone:     "catofes.",
			RootHash: []byte{1, 2, 3},
		}}},
	}

	data, err := MarshalMessage(message)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	got, err := UnmarshalMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalMessage: %v", err)
	}
	if got.Type != MessagePing || got.PeerID != "node-a" || len(got.Ping.Zones) != 1 {
		t.Fatalf("decoded message = %#v", got)
	}
	if got.Ping.Zones[0].Zone != "catofes." || !bytes.Equal(got.Ping.Zones[0].RootHash, []byte{1, 2, 3}) {
		t.Fatalf("decoded digest = %#v", got.Ping.Zones[0])
	}
}

func TestRejectsInvalidMessageShape(t *testing.T) {
	_, err := MarshalMessage(&Message{
		Type:      MessageFetchRecord,
		PeerID:    "node-a",
		Nonce:     1,
		Timestamp: 123,
		FetchRecord: &FetchRecord{
			Zone: "catofes.",
		},
	})
	if err == nil {
		t.Fatalf("MarshalMessage accepted fetch_record without key")
	}
}

func TestRejectsUnsupportedWireVersion(t *testing.T) {
	_, err := MarshalMessage(&Message{
		Version:   WireVersion + 1,
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     1,
		Timestamp: 123,
		Ping:      &Ping{},
	})
	if err == nil {
		t.Fatalf("MarshalMessage accepted unsupported wire version")
	}
}

func TestReplayWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	rw := NewReplayWindow(5 * time.Minute)

	if err := rw.Check("node-a", 1, now.Unix(), now); err != nil {
		t.Fatalf("Check(first): %v", err)
	}
	if err := rw.Check("node-a", 1, now.Unix(), now); !errors.Is(err, ErrReplay) {
		t.Fatalf("Check(replay) = %v, want ErrReplay", err)
	}
	if err := rw.Check("node-a", 2, now.Add(-6*time.Minute).Unix(), now); !errors.Is(err, ErrMessageExpired) {
		t.Fatalf("Check(expired) = %v, want ErrMessageExpired", err)
	}
}

func TestPeerQuotas(t *testing.T) {
	now := time.Unix(1000, 0)
	quotas := NewPeerQuotas(QuotaConfig{
		ByteRate:    10,
		ByteBurst:   10,
		ObjectRate:  1,
		ObjectBurst: 1,
	})

	if err := quotas.Allow("node-a", 9, 1, now); err != nil {
		t.Fatalf("Allow(first): %v", err)
	}
	if err := quotas.Allow("node-a", 2, 1, now); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("Allow(over quota) = %v, want ErrQuotaExceeded", err)
	}
	if err := quotas.Allow("node-a", 10, 1, now.Add(time.Second)); err != nil {
		t.Fatalf("Allow(refilled): %v", err)
	}
}

func TestZoneDigestsAreStable(t *testing.T) {
	ns := zone.NewNetworkState()
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
	})
	ns.Zones["catofes."].Records["identity"] = &zone.Record{
		Zone:      "catofes.",
		Key:       "identity",
		Type:      "node.identity",
		Value:     []byte("node"),
		ValueHash: []byte{1},
		Version:   1,
		Timestamp: 123,
	}
	first := ZoneDigests(ns)
	second := ZoneDigests(ns)
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("ZoneDigests lengths = %d/%d, want 1/1", len(first), len(second))
	}
	if !bytes.Equal(first[0].RootHash, second[0].RootHash) {
		t.Fatalf("ZoneDigests root hash changed for same state")
	}
}

func TestApplySnapshotVerifiesAndMergesWholeZone(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePriv := testNetwork(t)
	source.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)

	v1 := signedRecord(t, zonePriv, "catofes.", "identity", []byte("node-a"), 1, nil, now.Unix())
	if err := source.PutAt(v1, now); err != nil {
		t.Fatalf("PutAt(v1): %v", err)
	}
	v2 := signedRecord(t, zonePriv, "catofes.", "identity", []byte("node-b"), 2, higgscrypto.RecordHash(v1), now.Unix()+1)
	if err := source.PutAt(v2, now); err != nil {
		t.Fatalf("PutAt(v2): %v", err)
	}

	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snapshot.RecordHistory) != 0 {
		t.Fatalf("snapshot history len = %d, want 0", len(snapshot.RecordHistory))
	}

	target := cloneNetworkState(source)
	target.Zones["catofes."].Records = make(map[string]*zone.Record)
	target.Zones["catofes."].RecordHistory = make(map[string][]*zone.Record)
	target.Zones["catofes."].Records["obsolete"] = signedRecord(t, zonePriv, "catofes.", "obsolete", []byte("old"), 1, nil, now.Unix())
	result, err := ApplySnapshot(target, snapshot, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if result.Records != 1 {
		t.Fatalf("applied records = %d, want 1", result.Records)
	}
	got := target.Zones["catofes."].Records["identity"]
	if got == nil || string(got.Value) != "node-b" || got.Version != 2 {
		t.Fatalf("active record = %#v, want v2", got)
	}
	if target.Zones["catofes."].Records["obsolete"] == nil {
		t.Fatalf("trusted local key was removed by whole-zone snapshot")
	}
}

func TestApplyRecordSnapshotAcceptsSignedFastForward(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePriv := testNetwork(t)
	source.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)

	v1 := signedRecord(t, zonePriv, "catofes.", "identity", []byte("node-a"), 1, nil, now.Unix())
	v2 := signedRecord(t, zonePriv, "catofes.", "identity", []byte("node-b"), 2, higgscrypto.RecordHash(v1), now.Unix()+1)
	if err := source.PutAt(v1, now); err != nil {
		t.Fatalf("PutAt(v1): %v", err)
	}
	if err := source.PutAt(v2, now); err != nil {
		t.Fatalf("PutAt(v2): %v", err)
	}

	target := cloneNetworkState(source)
	target.Zones["catofes."].Records = make(map[string]*zone.Record)
	target.Zones["catofes."].RecordHistory = make(map[string][]*zone.Record)

	if err := ApplyRecordSnapshot(target, &RecordSnapshot{Zone: "catofes.", Record: v2}, now); err != nil {
		t.Fatalf("ApplyRecordSnapshot(v2): %v", err)
	}
	got := target.Zones["catofes."].Records["identity"]
	if got == nil || got.Version != 2 || string(got.Value) != "node-b" {
		t.Fatalf("active record = %#v, want v2", got)
	}
}

func TestRevocationTombstoneQuarantinesChildZone(t *testing.T) {
	now := time.Unix(1000, 0)
	source, rootPriv, zonePriv := testNetworkWithKeys(t)
	source.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)

	delegation := source.Zones[zone.RootZone].Delegations["catofes."]
	revocation := &zone.DelegationRevocation{
		ChildZone:             "catofes.",
		ParentZone:            zone.RootZone,
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		Reason:                "compromised",
		RevokedAt:             now.Unix(),
	}
	if err := higgscrypto.SignDelegationRevocation(revocation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegationRevocation: %v", err)
	}
	source.Zones[zone.RootZone].Revocations["catofes."] = revocation
	delete(source.Zones[zone.RootZone].Delegations, "catofes.")

	snapshot, err := Snapshot(source, zone.RootZone)
	if err != nil {
		t.Fatalf("Snapshot(root): %v", err)
	}
	target, _ := testNetwork(t)
	result, err := ApplySnapshot(target, snapshot, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot(root): %v", err)
	}
	if result.Delegation != 0 {
		t.Fatalf("delegations = %d, want 0", result.Delegation)
	}
	if !target.IsZoneRevoked("catofes.", now) {
		t.Fatalf("catofes. was not marked revoked")
	}
	if err := higgscrypto.VerifyChain(target, "catofes.", now); !errors.Is(err, zone.ErrZoneRevoked) {
		t.Fatalf("VerifyChain = %v, want ErrZoneRevoked", err)
	}
	record := signedRecord(t, zonePriv, "catofes.", "identity", []byte("node-c"), 1, nil, now.Unix())
	if err := ApplyRecordSnapshot(target, &RecordSnapshot{Zone: "catofes.", Record: record}, now); !errors.Is(err, zone.ErrZoneRevoked) {
		t.Fatalf("ApplyRecordSnapshot = %v, want ErrZoneRevoked", err)
	}
}

func TestRevokedZoneEndpointsAreNotDiscovered(t *testing.T) {
	now := time.Unix(1000, 0)
	ns, rootPriv, zonePriv := testNetworkWithKeys(t)
	ns.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
	value := []byte(`{"endpoints":[{"address":"192.0.2.10","port":33434,"protocol":"udp"}],"updated_at":1000}`)
	record := signedRecord(t, zonePriv, "catofes.", EndpointRecordKeyUDP, value, 1, nil, now.Unix())
	if err := ns.PutAt(record, now); err != nil {
		t.Fatalf("PutAt(endpoint): %v", err)
	}
	if got := ExtractPeerEndpointsAt(ns, now); len(got["catofes."]) != 1 {
		t.Fatalf("endpoints before revoke = %#v, want one", got)
	}
	delegation := ns.Zones[zone.RootZone].Delegations["catofes."]
	revocation := &zone.DelegationRevocation{
		ChildZone:             "catofes.",
		ParentZone:            zone.RootZone,
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		Reason:                "retired",
		RevokedAt:             now.Unix(),
	}
	if err := higgscrypto.SignDelegationRevocation(revocation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegationRevocation: %v", err)
	}
	ns.Zones[zone.RootZone].Revocations["catofes."] = revocation
	if got := ExtractPeerEndpointsAt(ns, now); len(got["catofes."]) != 0 {
		t.Fatalf("endpoints after revoke = %#v, want none", got)
	}
}

func TestApplySnapshotRejectsRecordLimit(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePriv := testNetwork(t)
	source.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
	if err := source.PutAt(signedRecord(t, zonePriv, "catofes.", "identity", []byte("node-a"), 1, nil, now.Unix()), now); err != nil {
		t.Fatalf("PutAt(identity): %v", err)
	}
	if err := source.PutAt(signedRecord(t, zonePriv, "catofes.", "status", []byte("ready"), 1, nil, now.Unix()), now); err != nil {
		t.Fatalf("PutAt(status): %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	target := emptySnapshotTarget(source)
	if _, err := ApplySnapshot(target, snapshot, now, SyncLimits{MaxRecords: 0, MaxBytes: DefaultMaxMessage}); err != nil {
		t.Fatalf("ApplySnapshot without record limit: %v", err)
	}
	target = emptySnapshotTarget(source)
	if _, err := ApplySnapshot(target, snapshot, now, SyncLimits{MaxRecords: 2, MaxBytes: DefaultMaxMessage}); err != nil {
		t.Fatalf("ApplySnapshot at record limit: %v", err)
	}
	target = emptySnapshotTarget(source)
	if _, err := ApplySnapshot(target, snapshot, now, SyncLimits{MaxRecords: 0, MaxBytes: 1}); !errors.Is(err, ErrZoneSnapshotTooLarge) {
		t.Fatalf("ApplySnapshot byte limit = %v, want ErrZoneSnapshotTooLarge", err)
	}
	target = emptySnapshotTarget(source)
	if _, err := ApplySnapshot(target, snapshot, now, SyncLimits{MaxRecords: 1, MaxBytes: DefaultMaxMessage}); !errors.Is(err, ErrZoneSnapshotTooLarge) {
		t.Fatalf("ApplySnapshot record limit = %v, want ErrZoneSnapshotTooLarge", err)
	}
}

func TestApplySnapshotAcceptsAndRejectsByteBoundary(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePriv := testNetwork(t)
	source.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
	if err := source.PutAt(signedRecord(t, zonePriv, "catofes.", "identity", []byte("node-a"), 1, nil, now.Unix()), now); err != nil {
		t.Fatalf("PutAt(identity): %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("Marshal(snapshot): %v", err)
	}

	target := emptySnapshotTarget(source)
	if _, err := ApplySnapshot(target, snapshot, now, SyncLimits{MaxRecords: 1, MaxBytes: len(data)}); err != nil {
		t.Fatalf("ApplySnapshot at byte limit: %v", err)
	}
	target = emptySnapshotTarget(source)
	if _, err := ApplySnapshot(target, snapshot, now, SyncLimits{MaxRecords: 1, MaxBytes: len(data) - 1}); !errors.Is(err, ErrZoneSnapshotTooLarge) {
		t.Fatalf("ApplySnapshot below byte limit = %v, want ErrZoneSnapshotTooLarge", err)
	}
}

func emptySnapshotTarget(source *zone.NetworkState) *zone.NetworkState {
	target := cloneNetworkState(source)
	target.Zones["catofes."].Records = make(map[string]*zone.Record)
	target.Zones["catofes."].RecordHistory = make(map[string][]*zone.Record)
	return target
}

func testNetwork(t *testing.T) (*zone.NetworkState, ed25519.PrivateKey) {
	t.Helper()
	ns, _, zonePriv := testNetworkWithKeys(t)
	return ns, zonePriv
}

func testNetworkWithKeys(t *testing.T) (*zone.NetworkState, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	zonePub, zonePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(zone): %v", err)
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: higgscrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	})
	authority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: higgscrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: zonePub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate},
			}},
		}},
	}
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", authority)
	delegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *authority,
	}
	if err := higgscrypto.SignDelegation(delegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	ns.Zones[zone.RootZone].Delegations["catofes."] = delegation
	return ns, rootPriv, zonePriv
}

func signedRecord(t *testing.T, priv ed25519.PrivateKey, path zone.ZonePath, key string, value []byte, version uint64, prev []byte, ts int64) *zone.Record {
	t.Helper()
	record := &zone.Record{
		Zone:      path,
		Key:       key,
		Type:      "node.identity",
		Value:     value,
		Version:   version,
		PrevHash:  prev,
		Timestamp: ts,
	}
	if err := higgscrypto.SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	return record
}

func TestTransportSendReceiveKnownPeer(t *testing.T) {
	now := time.Unix(1000, 0)
	a, err := Listen(Config{
		PeerID:     "node-a",
		ListenAddr: "127.0.0.1:0",
		Clock:      func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(a): %v", err)
	}
	defer a.Close()

	b, err := Listen(Config{
		PeerID:     "node-b",
		ListenAddr: "127.0.0.1:0",
		KnownPeers: map[string]*net.UDPAddr{
			"node-a": a.LocalAddr(),
		},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(b): %v", err)
	}
	defer b.Close()

	a.AddPeer("node-b", b.LocalAddr())
	if err := a.Send("node-b", &Message{
		Type: MessagePing,
		Ping: &Ping{},
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	packet, err := b.Receive()
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if packet.Message.Type != MessagePing || packet.Message.PeerID != "node-a" {
		t.Fatalf("received message = %#v", packet.Message)
	}
}

func TestTransportRejectsUnknownPeer(t *testing.T) {
	now := time.Unix(1000, 0)
	a, err := Listen(Config{
		PeerID:     "node-a",
		ListenAddr: "127.0.0.1:0",
		Clock:      func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(a): %v", err)
	}
	defer a.Close()

	b, err := Listen(Config{
		PeerID:     "node-b",
		ListenAddr: "127.0.0.1:0",
		Clock:      func() time.Time { return now },
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(b): %v", err)
	}
	defer b.Close()

	a.AddPeer("node-b", b.LocalAddr())
	if err := a.Send("node-b", &Message{
		Type: MessagePing,
		Ping: &Ping{},
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if _, err := b.Receive(); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("Receive = %v, want ErrUnknownPeer", err)
	}
}

func skipRestrictedSocket(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, os.ErrPermission) {
		t.Skipf("UDP sockets are not permitted in this environment: %v", err)
	}
}
