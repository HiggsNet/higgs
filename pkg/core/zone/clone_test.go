package zone

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestCloneNetworkStateDeepCopiesMutableStateAndPreservesShape(t *testing.T) {
	expiresAt := time.Unix(2000, 0)
	authority := &ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []AuthorizedKey{{
			Key: []byte("authority-key"),
			Capabilities: []Capability{{
				Permissions: []Permission{PermWrite, PermDelegate},
				KeyPrefix:   "routes/",
			}},
		}},
	}
	delegation := &Delegation{
		ZoneName:      "node.catofes.",
		AuthorityHash: []byte("authority-hash"),
		Authority:     *authority,
		ExpiresAt:     &expiresAt,
		SignedBy:      []byte("delegation-signer"),
		Signature:     []byte("delegation-signature"),
	}
	record := &Record{
		Zone:      "catofes.",
		Key:       "identity",
		Value:     []byte("value"),
		ValueHash: []byte("value-hash"),
		PrevHash:  []byte("prev-hash"),
		SignedBy:  []byte("record-signer"),
		Signature: []byte("record-signature"),
		Version:   2,
	}
	verifier := func(*Record, *ZoneAuthority, time.Time) error { return nil }
	hasher := func(*Record) []byte { return []byte("hash") }
	original := &NetworkState{
		Zones: map[ZonePath]*ZoneState{
			"catofes.": {
				Path:        "catofes.",
				Authority:   authority,
				ParentProof: []*Delegation{delegation},
				Delegations: map[ZonePath]*Delegation{"node.catofes.": delegation},
				Revocations: map[ZonePath]*DelegationRevocation{
					"old.catofes.": {
						ChildZone:             "old.catofes.",
						RevokedAuthorityHash:  []byte("revoked-hash"),
						SignedBy:              []byte("revocation-signer"),
						Signature:             []byte("revocation-signature"),
						RevokedAuthorityEpoch: 1,
					},
				},
				Records:       map[string]*Record{"identity": record},
				RecordHistory: map[string][]*Record{"identity": {record, nil}},
				MerkleRoot:    []byte("merkle-root"),
			},
			"empty.catofes.": {
				Path:          "empty.catofes.",
				ParentProof:   []*Delegation{},
				Delegations:   map[ZonePath]*Delegation{},
				Revocations:   map[ZonePath]*DelegationRevocation{},
				Records:       map[string]*Record{},
				RecordHistory: map[string][]*Record{"empty": {}},
				MerkleRoot:    []byte{},
			},
			"nil.catofes.": nil,
		},
		GlobalRoot:     []byte("global-root"),
		RecordVerifier: verifier,
		RecordHasher:   hasher,
	}

	cloned := CloneNetworkState(original)
	assertJSONEqual(t, original, cloned)
	if reflect.ValueOf(cloned.RecordVerifier).Pointer() != reflect.ValueOf(verifier).Pointer() ||
		reflect.ValueOf(cloned.RecordHasher).Pointer() != reflect.ValueOf(hasher).Pointer() {
		t.Fatal("validation hooks were not retained")
	}
	empty := cloned.Zones["empty.catofes."]
	if empty.ParentProof == nil || empty.Delegations == nil || empty.Revocations == nil ||
		empty.Records == nil || empty.RecordHistory["empty"] == nil || empty.MerkleRoot == nil {
		t.Fatalf("non-nil empty shape was not preserved: %#v", empty)
	}
	if value, ok := cloned.Zones["nil.catofes."]; !ok || value != nil {
		t.Fatalf("nil zone entry was not preserved: present=%t value=%#v", ok, value)
	}

	cloned.GlobalRoot[0] = 'G'
	cloned.Zones["catofes."].Authority.Keys[0].Key[0] = 'K'
	cloned.Zones["catofes."].Authority.Keys[0].Capabilities[0].Permissions[0] = PermAllocateIP
	cloned.Zones["catofes."].ParentProof[0].AuthorityHash[0] = 'P'
	cloned.Zones["catofes."].Delegations["node.catofes."].Signature[0] = 'D'
	cloned.Zones["catofes."].Revocations["old.catofes."].Signature[0] = 'R'
	cloned.Zones["catofes."].Records["identity"].Value[0] = 'V'
	cloned.Zones["catofes."].RecordHistory["identity"][0].Signature[0] = 'H'
	cloned.Zones["catofes."].MerkleRoot[0] = 'M'
	if string(original.GlobalRoot) != "global-root" ||
		string(original.Zones["catofes."].Authority.Keys[0].Key) != "authority-key" ||
		original.Zones["catofes."].Authority.Keys[0].Capabilities[0].Permissions[0] != PermWrite ||
		string(original.Zones["catofes."].ParentProof[0].AuthorityHash) != "authority-hash" ||
		string(original.Zones["catofes."].Delegations["node.catofes."].Signature) != "delegation-signature" ||
		string(original.Zones["catofes."].Revocations["old.catofes."].Signature) != "revocation-signature" ||
		string(original.Zones["catofes."].Records["identity"].Value) != "value" ||
		string(original.Zones["catofes."].RecordHistory["identity"][0].Signature) != "record-signature" ||
		string(original.Zones["catofes."].MerkleRoot) != "merkle-root" {
		t.Fatal("clone mutation leaked into original network state")
	}

	original.Zones["catofes."].Records["identity"].PrevHash[0] = 'O'
	if string(cloned.Zones["catofes."].Records["identity"].PrevHash) != "prev-hash" {
		t.Fatal("original mutation leaked into cloned network state")
	}
}

func TestCloneNetworkStateSchemaGuard(t *testing.T) {
	assertStructFields(t, NetworkState{}, "Zones", "GlobalRoot", "RecordVerifier", "RecordHasher")
	assertStructFields(t, ZoneState{}, "Path", "Authority", "ParentProof", "Delegations", "Revocations", "Records", "RecordHistory", "MerkleRoot")
	assertStructFields(t, ZoneAuthority{}, "Zone", "Epoch", "Keys", "Threshold")
	assertStructFields(t, AuthorizedKey{}, "Key", "NotBefore", "NotAfter", "Capabilities")
	assertStructFields(t, Capability{}, "Permissions", "KeyPrefix")
	assertStructFields(t, Delegation{}, "ZoneName", "Scope", "AuthorityEpoch", "AuthorityHash", "Authority", "ExpiresAt", "SignedBy", "Signature")
	assertStructFields(t, DelegationRevocation{}, "ChildZone", "ParentZone", "RevokedAuthorityEpoch", "RevokedAuthorityHash", "Reason", "RevokedAt", "TTLSeconds", "GraceSeconds", "SignedBy", "Signature")
	assertStructFields(t, Record{}, "Zone", "Key", "Type", "Value", "ValueHash", "Version", "PrevHash", "Timestamp", "SignedBy", "Signature")
}

func assertJSONEqual(t *testing.T, want, got any) {
	t.Helper()
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal(want): %v", err)
	}
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal(got): %v", err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("JSON differs:\nwant: %s\ngot:  %s", wantJSON, gotJSON)
	}
}

func assertStructFields(t *testing.T, value any, expected ...string) {
	t.Helper()
	typ := reflect.TypeOf(value)
	if typ.NumField() != len(expected) {
		t.Fatalf("%s field count = %d, want %d (%v)", typ, typ.NumField(), len(expected), expected)
	}
	for i, name := range expected {
		if got := typ.Field(i).Name; got != name {
			t.Fatalf("%s field %d = %s, want %s", typ, i, got, name)
		}
	}
}
