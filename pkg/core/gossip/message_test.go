package gossip

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/Catofes/photon/pkg/core/zone"
	photoncrypto "github.com/Catofes/photon/pkg/crypto"
	"github.com/vmihailenco/msgpack/v5"
)

func TestMarshalUnmarshalPing(t *testing.T) {
	message := &Message{
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     1,
		Timestamp: 123,
		Ping: &Ping{Summary: &CatalogSummary{
			CatalogRoot: []byte{1, 2, 3},
			ZoneCount:   1,
		}},
	}

	data, err := MarshalMessage(message)
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	got, err := UnmarshalMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalMessage: %v", err)
	}
	if got.Type != MessagePing || got.PeerID != "node-a" || got.Ping.Summary == nil {
		t.Fatalf("decoded message = %#v", got)
	}
	if got.Ping.Summary.ZoneCount != 1 || !bytes.Equal(got.Ping.Summary.CatalogRoot, []byte{1, 2, 3}) {
		t.Fatalf("decoded summary = %#v", got.Ping.Summary)
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

func TestReplayWindowPrunesInactivePeers(t *testing.T) {
	now := time.Unix(1000, 0)
	rw := NewReplayWindow(5 * time.Minute)

	if err := rw.Check("node-a", 1, now.Unix(), now); err != nil {
		t.Fatalf("Check(node-a): %v", err)
	}
	if _, ok := rw.seen["node-a"]; !ok {
		t.Fatalf("node-a replay state was not recorded")
	}

	later := now.Add(6 * time.Minute)
	if err := rw.Check("node-b", 1, later.Unix(), later); err != nil {
		t.Fatalf("Check(node-b): %v", err)
	}
	if _, ok := rw.seen["node-a"]; ok {
		t.Fatalf("inactive peer replay state was not pruned: %#v", rw.seen)
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
	} else {
		var quotaErr *QuotaExceededError
		if !errors.As(err, &quotaErr) {
			t.Fatalf("Allow(over quota) did not return QuotaExceededError: %T", err)
		}
		if quotaErr.RequestedBytes != 2 || quotaErr.AvailableBytes != 1 || quotaErr.RequestedObjects != 1 || quotaErr.AvailableObjects != 0 {
			t.Fatalf("quota diagnostics = %#v, want requested 2/1 available 1/0", quotaErr)
		}
	}
	if err := quotas.Allow("node-a", 10, 1, now.Add(time.Second)); err != nil {
		t.Fatalf("Allow(refilled): %v", err)
	}
}

func TestPeerQuotasPrunesInactivePeers(t *testing.T) {
	now := time.Unix(1000, 0)
	quotas := NewPeerQuotas(QuotaConfig{
		ByteRate:    10,
		ByteBurst:   10,
		ObjectRate:  1,
		ObjectBurst: 1,
		PeerTTL:     time.Minute,
	})

	if err := quotas.Allow("node-a", 1, 1, now); err != nil {
		t.Fatalf("Allow(node-a): %v", err)
	}
	if _, ok := quotas.peers["node-a"]; !ok {
		t.Fatalf("node-a quota state was not recorded")
	}

	later := now.Add(2 * time.Minute)
	if err := quotas.Allow("node-b", 1, 1, later); err != nil {
		t.Fatalf("Allow(node-b): %v", err)
	}
	if _, ok := quotas.peers["node-a"]; ok {
		t.Fatalf("inactive peer quota state was not pruned: %#v", quotas.peers)
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
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)

	v1 := signedRecord(t, zonePriv, "catofes.", "identity", []byte("node-a"), 1, nil, now.Unix())
	if err := source.PutAt(v1, now); err != nil {
		t.Fatalf("PutAt(v1): %v", err)
	}
	v2 := signedRecord(t, zonePriv, "catofes.", "identity", []byte("node-b"), 2, photoncrypto.RecordHash(v1), now.Unix()+1)
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
	result, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits())
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

func TestApplySnapshotTrustFailureLeavesNetworkUnchanged(t *testing.T) {
	now := time.Unix(1000, 0)
	source, _ := testNetwork(t)
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	untrustedPublicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(untrusted): %v", err)
	}
	snapshot.Authority.Keys[0].Key = untrustedPublicKey

	target := snapshotAtomicityTarget(source)
	before := captureNetworkState(t, target)
	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); !errors.Is(err, ErrUntrustedZone) {
		t.Fatalf("ApplySnapshot = %v, want ErrUntrustedZone", err)
	}
	assertNetworkStateUnchanged(t, target, before)
}

func TestApplySnapshotDelegationFailureLeavesNetworkUnchanged(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePrivateKey := testNetwork(t)
	childPublicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(child): %v", err)
	}
	childAuthority := zone.ZoneAuthority{
		Zone:      "node-a.catofes.",
		Epoch:     1,
		Threshold: photoncrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: childPublicKey,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	delegation := &zone.Delegation{
		ZoneName:  childAuthority.Zone,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: childAuthority,
	}
	if err := photoncrypto.SignDelegation(delegation, "catofes.", zonePrivateKey); err != nil {
		t.Fatalf("SignDelegation(child): %v", err)
	}
	delegation.Signature[0] ^= 0xff

	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	snapshot.Delegations[delegation.ZoneName] = delegation

	target := snapshotAtomicityTarget(source)
	before := captureNetworkState(t, target)
	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); err == nil {
		t.Fatal("ApplySnapshot succeeded with an invalid delegation")
	}
	assertNetworkStateUnchanged(t, target, before)
}

func TestApplySnapshotRevocationFailureLeavesNetworkUnchanged(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePrivateKey := testNetwork(t)
	revocation := &zone.DelegationRevocation{
		ChildZone:             "node-a.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: 1,
		RevokedAuthorityHash:  []byte("child-authority"),
		Reason:                "test",
		RevokedAt:             now.Unix(),
	}
	if err := photoncrypto.SignDelegationRevocation(revocation, "catofes.", zonePrivateKey); err != nil {
		t.Fatalf("SignDelegationRevocation(child): %v", err)
	}
	revocation.Signature[0] ^= 0xff

	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	snapshot.Revocations[revocation.ChildZone] = revocation

	target := snapshotAtomicityTarget(source)
	before := captureNetworkState(t, target)
	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); err == nil {
		t.Fatal("ApplySnapshot succeeded with an invalid revocation")
	}
	assertNetworkStateUnchanged(t, target, before)
}

func TestApplySnapshotRecordFailureAfterSuccessLeavesNetworkUnchanged(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePrivateKey := testNetwork(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	first := signedRecord(t, zonePrivateKey, "catofes.", "a-valid", []byte("first"), 1, nil, now.Unix())
	if err := source.PutAt(first, now); err != nil {
		t.Fatalf("PutAt(first): %v", err)
	}
	second := signedRecord(t, zonePrivateKey, "catofes.", "z-invalid", []byte("second"), 1, nil, now.Unix())
	if err := source.PutAt(second, now); err != nil {
		t.Fatalf("PutAt(second): %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	snapshot.Records["z-invalid"].Signature[0] ^= 0xff

	target := snapshotAtomicityTarget(source)
	delete(target.Zones["catofes."].Records, "a-valid")
	delete(target.Zones["catofes."].Records, "z-invalid")
	before := captureNetworkState(t, target)
	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); err == nil {
		t.Fatal("ApplySnapshot succeeded with an invalid second record")
	}
	assertNetworkStateUnchanged(t, target, before)
}

func TestApplySnapshotSkipsStaleAndConflictingRecords(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePrivateKey := testNetwork(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	stale := signedRecord(t, zonePrivateKey, "catofes.", "stale", []byte("remote-v1"), 1, nil, now.Unix())
	conflict := signedRecord(t, zonePrivateKey, "catofes.", "conflict", []byte("remote"), 1, nil, now.Unix())
	if err := source.PutAt(stale, now); err != nil {
		t.Fatalf("PutAt(stale): %v", err)
	}
	if err := source.PutAt(conflict, now); err != nil {
		t.Fatalf("PutAt(conflict): %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	target := cloneNetworkState(source)
	target.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	targetStaleV1 := signedRecord(t, zonePrivateKey, "catofes.", "stale", []byte("local-v1"), 1, nil, now.Unix())
	targetStaleV2 := signedRecord(t, zonePrivateKey, "catofes.", "stale", []byte("local-v2"), 2, photoncrypto.RecordHash(targetStaleV1), now.Unix()+1)
	target.Zones["catofes."].Records["stale"] = targetStaleV2
	target.Zones["catofes."].Records["conflict"] = signedRecord(t, zonePrivateKey, "catofes.", "conflict", []byte("local"), 1, nil, now.Unix())

	result, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if result.Records != 0 {
		t.Fatalf("applied records = %d, want 0", result.Records)
	}
	if got := string(target.Zones["catofes."].Records["stale"].Value); got != "local-v2" {
		t.Fatalf("stale record = %q, want local-v2", got)
	}
	if got := string(target.Zones["catofes."].Records["conflict"].Value); got != "local" {
		t.Fatalf("conflicting record = %q, want local", got)
	}
}

func TestApplySnapshotSuccessInstallsDetachedCandidate(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePrivateKey := testNetwork(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	v1 := signedRecord(t, zonePrivateKey, "catofes.", "identity", []byte("v1"), 1, nil, now.Unix())
	if err := source.PutAt(v1, now); err != nil {
		t.Fatalf("PutAt(v1): %v", err)
	}
	target := cloneNetworkState(source)
	target.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	target.Zones[zone.RootZone].RecordHistory = nil
	previousTargetZone := target.Zones["catofes."]

	v2 := signedRecord(t, zonePrivateKey, "catofes.", "identity", []byte("v2"), 2, photoncrypto.RecordHash(v1), now.Unix()+1)
	if err := source.PutAt(v2, now); err != nil {
		t.Fatalf("PutAt(v2): %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	result, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if result.Records != 1 {
		t.Fatalf("applied records = %d, want 1", result.Records)
	}
	if target.Zones["catofes."] == previousTargetZone {
		t.Fatal("successful apply retained the old mutable target zone")
	}
	if target.Zones[zone.RootZone].RecordHistory != nil {
		t.Fatalf("unrelated nil record history became non-nil: %#v", target.Zones[zone.RootZone].RecordHistory)
	}
	history := target.Zones["catofes."].RecordHistory["identity"]
	if len(history) != 1 || string(history[0].Value) != "v1" {
		t.Fatalf("record history = %#v, want detached v1", history)
	}

	previousTargetZone.Records["identity"].Value[0] = 'x'
	snapshot.Records["identity"].Value[0] = 'y'
	if got := string(target.Zones["catofes."].Records["identity"].Value); got != "v2" {
		t.Fatalf("installed record changed through retained input: %q", got)
	}
}

func TestApplySnapshotReturnsTargetZoneCOWCandidate(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePrivateKey := testNetwork(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	record := signedRecord(t, zonePrivateKey, "catofes.", "identity", []byte("remote"), 1, nil, now.Unix())
	if err := source.PutAt(record, now); err != nil {
		t.Fatalf("PutAt(record): %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	target := cloneNetworkState(source)
	delete(target.Zones["catofes."].Records, "identity")
	originalRoot := target.Zones[zone.RootZone]
	originalTarget := target.Zones["catofes."]
	candidate, result, err := ApplySnapshot(target, snapshot, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if result.Records != 1 {
		t.Fatalf("applied records = %d, want 1", result.Records)
	}
	if candidate == target {
		t.Fatal("candidate reused input NetworkState root")
	}
	if candidate.Zones[zone.RootZone] != originalRoot {
		t.Fatal("unmodified root zone was not structurally shared")
	}
	if candidate.Zones["catofes."] == originalTarget {
		t.Fatal("target zone was not detached")
	}
	if target.Zones["catofes."].Records["identity"] != nil {
		t.Fatal("candidate record update leaked into input NetworkState")
	}

	// The complete mutable target zone, including values nested below its
	// maps/slices, must be owned by the candidate.
	candidate.Zones["catofes."].Authority.Keys[0].Key[0] ^= 0xff
	candidate.Zones["catofes."].Records["identity"].Value[0] = 'x'
	if bytes.Equal(candidate.Zones["catofes."].Authority.Keys[0].Key, originalTarget.Authority.Keys[0].Key) {
		t.Fatal("target authority remained shared")
	}
	if target.Zones["catofes."].Records["identity"] != nil {
		t.Fatal("target records map remained shared")
	}
}

func TestApplySnapshotSequentialTargetZoneCOW(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePrivateKey := testNetwork(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	v1 := signedRecord(t, zonePrivateKey, "catofes.", "identity", []byte("v1"), 1, nil, now.Unix())
	if err := source.PutAt(v1, now); err != nil {
		t.Fatalf("PutAt(v1): %v", err)
	}
	snapshot1, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(v1): %v", err)
	}
	v2 := signedRecord(t, zonePrivateKey, "catofes.", "identity", []byte("v2"), 2, photoncrypto.RecordHash(v1), now.Unix()+1)
	if err := source.PutAt(v2, now); err != nil {
		t.Fatalf("PutAt(v2): %v", err)
	}
	snapshot2, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(v2): %v", err)
	}

	base := emptySnapshotTarget(source)
	first, _, err := ApplySnapshot(base, snapshot1, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot(v1): %v", err)
	}
	firstTarget := first.Zones["catofes."]
	second, _, err := ApplySnapshot(first, snapshot2, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot(v2): %v", err)
	}
	if second.Zones[zone.RootZone] != first.Zones[zone.RootZone] {
		t.Fatal("unmodified ancestor was not shared across sequential candidates")
	}
	if second.Zones["catofes."] == firstTarget {
		t.Fatal("second update reused first mutable target zone")
	}
	if got := string(firstTarget.Records["identity"].Value); got != "v1" {
		t.Fatalf("second update leaked into first candidate: %q", got)
	}
	if got := string(second.Zones["catofes."].Records["identity"].Value); got != "v2" {
		t.Fatalf("second candidate record = %q, want v2", got)
	}
}

func TestApplyChildSnapshotUsesParentProof(t *testing.T) {
	now := time.Unix(1000, 0)
	source, _, zonePriv := testNetworkWithKeys(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	nodePub, nodePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(node): %v", err)
	}
	nodeAuthority := &zone.ZoneAuthority{
		Zone:      "node-b.catofes.",
		Epoch:     1,
		Threshold: photoncrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: nodePub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	delegation := &zone.Delegation{
		ZoneName:  "node-b.catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *nodeAuthority,
	}
	if err := photoncrypto.SignDelegation(delegation, "catofes.", zonePriv); err != nil {
		t.Fatalf("SignDelegation(node-b): %v", err)
	}
	source.Zones["catofes."].Delegations["node-b.catofes."] = delegation
	source.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", nodeAuthority)
	record := signedRecord(t, nodePriv, "node-b.catofes.", "identity", []byte("node-b"), 1, nil, now.Unix())
	if err := source.PutAt(record, now); err != nil {
		t.Fatalf("PutAt(node-b): %v", err)
	}

	snapshot, err := Snapshot(source, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot(node-b): %v", err)
	}
	if len(snapshot.ParentProof) == 0 || snapshot.ParentProof[0].ZoneName != "node-b.catofes." {
		t.Fatalf("snapshot parent proof = %#v, want direct node-b delegation", snapshot.ParentProof)
	}

	target := cloneNetworkState(source)
	delete(target.Zones["catofes."].Delegations, zone.ZonePath("node-b.catofes."))
	delete(target.Zones, zone.ZonePath("node-b.catofes."))

	if _, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits()); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if err := photoncrypto.VerifyChain(target, "node-b.catofes.", now); err != nil {
		t.Fatalf("VerifyChain(node-b): %v", err)
	}
}

func TestRevocationTombstoneQuarantinesChildZone(t *testing.T) {
	now := time.Unix(1000, 0)
	source, rootPriv, _ := testNetworkWithKeys(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)

	delegation := source.Zones[zone.RootZone].Delegations["catofes."]
	revocation := &zone.DelegationRevocation{
		ChildZone:             "catofes.",
		ParentZone:            zone.RootZone,
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		Reason:                "compromised",
		RevokedAt:             now.Unix(),
	}
	if err := photoncrypto.SignDelegationRevocation(revocation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegationRevocation: %v", err)
	}
	source.Zones[zone.RootZone].Revocations["catofes."] = revocation
	delete(source.Zones[zone.RootZone].Delegations, "catofes.")

	snapshot, err := Snapshot(source, zone.RootZone)
	if err != nil {
		t.Fatalf("Snapshot(root): %v", err)
	}
	target, _ := testNetwork(t)
	result, err := applySnapshotForTest(target, snapshot, now, DefaultSyncLimits())
	if err != nil {
		t.Fatalf("ApplySnapshot(root): %v", err)
	}
	if result.Delegation != 0 {
		t.Fatalf("delegations = %d, want 0", result.Delegation)
	}
	if !target.IsZoneRevoked("catofes.", now) {
		t.Fatalf("catofes. was not marked revoked")
	}
	if err := photoncrypto.VerifyChain(target, "catofes.", now); !errors.Is(err, zone.ErrZoneRevoked) {
		t.Fatalf("VerifyChain = %v, want ErrZoneRevoked", err)
	}
}

func TestRevokedZoneEndpointsAreNotDiscovered(t *testing.T) {
	now := time.Unix(1000, 0)
	ns, rootPriv, zonePriv := testNetworkWithKeys(t)
	ns.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
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
	if err := photoncrypto.SignDelegationRevocation(revocation, zone.RootZone, rootPriv); err != nil {
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
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
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
	if _, err := applySnapshotForTest(target, snapshot, now, SyncLimits{MaxRecords: 0, MaxBytes: DefaultMaxMessage}); err != nil {
		t.Fatalf("ApplySnapshot without record limit: %v", err)
	}
	target = emptySnapshotTarget(source)
	if _, err := applySnapshotForTest(target, snapshot, now, SyncLimits{MaxRecords: 2, MaxBytes: DefaultMaxMessage}); err != nil {
		t.Fatalf("ApplySnapshot at record limit: %v", err)
	}
	target = emptySnapshotTarget(source)
	if _, err := applySnapshotForTest(target, snapshot, now, SyncLimits{MaxRecords: 0, MaxBytes: 1}); !errors.Is(err, ErrZoneSnapshotTooLarge) {
		t.Fatalf("ApplySnapshot byte limit = %v, want ErrZoneSnapshotTooLarge", err)
	}
	target = emptySnapshotTarget(source)
	if _, err := applySnapshotForTest(target, snapshot, now, SyncLimits{MaxRecords: 1, MaxBytes: DefaultMaxMessage}); !errors.Is(err, ErrZoneSnapshotTooLarge) {
		t.Fatalf("ApplySnapshot record limit = %v, want ErrZoneSnapshotTooLarge", err)
	}
}

func TestApplySnapshotAcceptsAndRejectsByteBoundary(t *testing.T) {
	now := time.Unix(1000, 0)
	source, zonePriv := testNetwork(t)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	if err := source.PutAt(signedRecord(t, zonePriv, "catofes.", "identity", []byte("node-a"), 1, nil, now.Unix()), now); err != nil {
		t.Fatalf("PutAt(identity): %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// Use msgpack for size check because it is the default wire codec.
	data, err := msgpack.Marshal(snapshot)
	if err != nil {
		t.Fatalf("Marshal(snapshot): %v", err)
	}

	target := emptySnapshotTarget(source)
	if _, err := applySnapshotForTest(target, snapshot, now, SyncLimits{MaxRecords: 1, MaxBytes: len(data)}); err != nil {
		t.Fatalf("ApplySnapshot at byte limit: %v", err)
	}
	target = emptySnapshotTarget(source)
	if _, err := applySnapshotForTest(target, snapshot, now, SyncLimits{MaxRecords: 1, MaxBytes: len(data) - 1}); !errors.Is(err, ErrZoneSnapshotTooLarge) {
		t.Fatalf("ApplySnapshot below byte limit = %v, want ErrZoneSnapshotTooLarge", err)
	}
}

// applySnapshotForTest preserves the older in-place test setup while the
// production API exposes candidate publication explicitly.
func applySnapshotForTest(ns *zone.NetworkState, snapshot *ZoneSnapshot, now time.Time, limits SyncLimits) (*ApplyResult, error) {
	candidate, result, err := ApplySnapshot(ns, snapshot, now, limits)
	if err != nil {
		return nil, err
	}
	*ns = *candidate
	return result, nil
}

func emptySnapshotTarget(source *zone.NetworkState) *zone.NetworkState {
	target := cloneNetworkState(source)
	target.Zones["catofes."].Records = make(map[string]*zone.Record)
	target.Zones["catofes."].RecordHistory = make(map[string][]*zone.Record)
	return target
}

type capturedNetworkState struct {
	data            []byte
	verifierPointer uintptr
	hasherPointer   uintptr
}

func snapshotAtomicityTarget(source *zone.NetworkState) *zone.NetworkState {
	target := cloneNetworkState(source)
	target.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	target.GlobalRoot = []byte("global-root")
	target.Zones["catofes."].MerkleRoot = []byte("zone-root")
	target.Zones["catofes."].RecordHistory["local"] = []*zone.Record{{
		Zone:    "catofes.",
		Key:     "local",
		Type:    "test",
		Value:   []byte("history"),
		Version: 1,
	}}
	return target
}

func captureNetworkState(t *testing.T, ns *zone.NetworkState) capturedNetworkState {
	t.Helper()
	data, err := json.Marshal(ns)
	if err != nil {
		t.Fatalf("Marshal(network state): %v", err)
	}
	return capturedNetworkState{
		data:            data,
		verifierPointer: reflect.ValueOf(ns.RecordVerifier).Pointer(),
		hasherPointer:   reflect.ValueOf(ns.RecordHasher).Pointer(),
	}
}

func assertNetworkStateUnchanged(t *testing.T, ns *zone.NetworkState, before capturedNetworkState) {
	t.Helper()
	data, err := json.Marshal(ns)
	if err != nil {
		t.Fatalf("Marshal(network state after apply): %v", err)
	}
	if !bytes.Equal(data, before.data) {
		t.Fatalf("network state changed after failed apply:\nbefore: %s\nafter:  %s", before.data, data)
	}
	if got := reflect.ValueOf(ns.RecordVerifier).Pointer(); got != before.verifierPointer {
		t.Fatalf("record verifier changed after failed apply: got %x, want %x", got, before.verifierPointer)
	}
	if got := reflect.ValueOf(ns.RecordHasher).Pointer(); got != before.hasherPointer {
		t.Fatalf("record hasher changed after failed apply: got %x, want %x", got, before.hasherPointer)
	}
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
		Threshold: photoncrypto.SupportedThreshold,
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
		Threshold: photoncrypto.SupportedThreshold,
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
	if err := photoncrypto.SignDelegation(delegation, zone.RootZone, rootPriv); err != nil {
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
	if err := photoncrypto.SignRecord(record, priv); err != nil {
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
