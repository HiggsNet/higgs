package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestStoreApplyLocalRecordIntentVersionsAndRetainsNoPointers(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _, identityPrivate, _ := managedAuthorityFixture(t, true)
	repository := &memoryVerifiedRepository{}
	store := NewStore(&VerifiedState{ManagedZone: "node-a.catofes.", Network: network, IdentityPrivateKey: identityPrivate}, repository)
	value := []byte("v1")
	first, err := store.ApplyLocalIntent(context.Background(), Revisions{}, PutRecordIntent{
		Zone: "node-a.catofes.", Key: "config", Type: "text", Value: value,
	}, now)
	if err != nil {
		t.Fatalf("ApplyLocalIntent(v1): %v", err)
	}
	if !first.Committed || first.Record == nil || first.Record.Version != 1 || first.Changes.SecurityPriority {
		t.Fatalf("first result = %+v", first)
	}
	value[0] = 'X'
	first.Record.Value[0] = 'Y'

	second, err := store.ApplyLocalIntent(context.Background(), first.Changes.Revisions, PutRecordIntent{
		Zone: "node-a.catofes.", Key: "config", Type: "text", Value: []byte("v2"),
	}, now.Add(time.Second))
	if err != nil {
		t.Fatalf("ApplyLocalIntent(v2): %v", err)
	}
	if second.Record.Version != 2 {
		t.Fatalf("second version = %d, want 2", second.Record.Version)
	}
	view := store.ReadView()
	managed := view.State.Network.Zones["node-a.catofes."]
	if string(managed.Records["config"].Value) != "v2" || len(managed.RecordHistory["config"]) != 1 || string(managed.RecordHistory["config"][0].Value) != "v1" {
		t.Fatalf("record/history = %#v/%#v", managed.Records["config"], managed.RecordHistory["config"])
	}
	if repository.commits != 2 || view.Revisions != (Revisions{Verified: 2}) {
		t.Fatalf("commits/revisions = %d/%+v", repository.commits, view.Revisions)
	}
	if !bytes.Equal(repository.state.IdentityPrivateKey, identityPrivate) || !bytes.Equal(view.State.IdentityPrivateKey, identityPrivate) {
		t.Fatal("raw identity private key was not retained in repository/read state")
	}
	view.State.IdentityPrivateKey[0] ^= 0xff
	if !bytes.Equal(store.ReadView().State.IdentityPrivateKey, identityPrivate) {
		t.Fatal("read view private key was not detached")
	}
}

func TestStoreApplyLocalIntentRejectsMissingAndUnauthorizedKey(t *testing.T) {
	network, _, _, _ := managedAuthorityFixture(t, true)
	store := NewStore(&VerifiedState{Network: network}, nil)
	intent := PutRecordIntent{Zone: "node-a.catofes.", Key: "config", Type: "text", Value: []byte("value")}
	if _, err := store.ApplyLocalIntent(context.Background(), Revisions{}, intent, time.Unix(1000, 0)); err == nil {
		t.Fatal("missing private key was accepted")
	}
	_, otherPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(other): %v", err)
	}
	store = NewStore(&VerifiedState{Network: network, IdentityPrivateKey: otherPrivate}, nil)
	if _, err := store.ApplyLocalIntent(context.Background(), Revisions{}, intent, time.Unix(1000, 0)); err == nil {
		t.Fatal("unauthorized signer was accepted")
	}
	if view := store.ReadView(); view.Revisions != (Revisions{}) || view.State.Network.Zones["node-a.catofes."].Records["config"] != nil {
		t.Fatalf("failed signing published state: %+v", view)
	}
}

func TestStoreApplyLocalDelegationThenRevocationCleansPeerMetadata(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _, _, parentPrivate := managedAuthorityFixture(t, true)
	childPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(child): %v", err)
	}
	childAuthority := &zone.ZoneAuthority{Zone: "new.catofes.", Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{
		Key: childPublic, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}},
	}}}
	store := NewStore(&VerifiedState{Network: network, Peers: map[string]PeerSyncMetadata{
		"new.catofes.":      {LastSyncUnix: 1},
		"leaf.new.catofes.": {LastSyncUnix: 1},
		"other.catofes.":    {LastSyncUnix: 1},
	}, ManagedZone: "catofes.", IdentityPrivateKey: parentPrivate}, nil)
	issued, err := store.ApplyLocalIntent(context.Background(), Revisions{}, PutDelegationIntent{Parent: "catofes.", Authority: childAuthority}, now)
	if err != nil {
		t.Fatalf("PutDelegation: %v", err)
	}
	if issued.Delegation == nil || issued.Changes.SecurityPriority {
		t.Fatalf("issued result = %+v", issued)
	}
	revoked, err := store.ApplyLocalIntent(context.Background(), issued.Changes.Revisions, RevokeDelegationIntent{
		Parent: "catofes.", Child: "new.catofes.", Reason: "compromised",
	}, now.Add(time.Second))
	if err != nil {
		t.Fatalf("RevokeDelegation: %v", err)
	}
	if revoked.Revocation == nil || !revoked.Changes.SecurityPriority || !revoked.Changes.PeerMetadataChanged {
		t.Fatalf("revoked result = %+v", revoked)
	}
	view := store.ReadView()
	parent := view.State.Network.Zones["catofes."]
	if parent.Delegations["new.catofes."] != nil || parent.Revocations["new.catofes."] == nil {
		t.Fatalf("parent delegation/revocation = %#v/%#v", parent.Delegations["new.catofes."], parent.Revocations["new.catofes."])
	}
	if _, ok := view.State.Peers["new.catofes."]; ok {
		t.Fatal("revoked peer metadata retained")
	}
	if _, ok := view.State.Peers["leaf.new.catofes."]; ok {
		t.Fatal("revoked descendant metadata retained")
	}
	if _, ok := view.State.Peers["other.catofes."]; !ok {
		t.Fatal("unrelated peer metadata removed")
	}
	if view.Revisions != (Revisions{Verified: 2, Metadata: 1}) {
		t.Fatalf("revisions = %+v, want verified=2 metadata=1", view.Revisions)
	}
}

func TestStoreApplyLocalIntentRepositoryFailureDoesNotPublish(t *testing.T) {
	network, _, identityPrivate, _ := managedAuthorityFixture(t, true)
	wantErr := errors.New("local commit failed")
	store := NewStore(&VerifiedState{Network: network, IdentityPrivateKey: identityPrivate}, &memoryVerifiedRepository{err: wantErr})
	_, err := store.ApplyLocalIntent(context.Background(), Revisions{}, PutRecordIntent{
		Zone: "node-a.catofes.", Key: "config", Type: "text", Value: []byte("value"),
	}, time.Unix(1000, 0))
	if !errors.Is(err, wantErr) {
		t.Fatalf("ApplyLocalIntent error = %v, want %v", err, wantErr)
	}
	view := store.ReadView()
	if view.Revisions != (Revisions{}) || view.State.Network.Zones["node-a.catofes."].Records["config"] != nil {
		t.Fatalf("repository failure published local intent: %+v", view)
	}
}
