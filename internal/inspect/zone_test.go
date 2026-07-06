package inspect

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func TestBuildZoneDetailSortsRecordsAndIncludesHistory(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	authority := &zone.ZoneAuthority{
		Zone:      "node-a.catofes.",
		Epoch:     7,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
				KeyPrefix:   "identity",
			}},
		}},
	}
	active := &zone.Record{
		Zone:      "node-a.catofes.",
		Key:       "identity",
		Type:      "profile",
		Value:     []byte(`{"name":"node-a"}`),
		ValueHash: []byte{0x01},
		Version:   2,
		Timestamp: 20,
	}
	if err := higgscrypto.SignRecord(active, priv); err != nil {
		t.Fatalf("SignRecord(active): %v", err)
	}
	old := &zone.Record{
		Zone:      "node-a.catofes.",
		Key:       "identity",
		Type:      "profile",
		Value:     []byte("old"),
		Version:   1,
		Timestamp: 10,
	}
	if err := higgscrypto.SignRecord(old, priv); err != nil {
		t.Fatalf("SignRecord(old): %v", err)
	}
	zs := zone.NewZoneState("node-a.catofes.", authority)
	zs.Records["identity"] = active
	zs.RecordHistory["identity"] = []*zone.Record{old}
	ns := &zone.NetworkState{Zones: map[zone.ZonePath]*zone.ZoneState{"node-a.catofes.": zs}}

	got := BuildZoneDetail(ZoneDetailInput{
		Path:           "node-a.catofes.",
		State:          zs,
		Network:        ns,
		Now:            time.Unix(100, 0),
		IncludeHistory: true,
	})

	if got.Path != "node-a.catofes." || got.Parent != "catofes." {
		t.Fatalf("path/parent = %q/%q", got.Path, got.Parent)
	}
	if got.Authority == nil || got.Authority.Epoch != 7 || got.AuthorityHash == "" {
		t.Fatalf("authority view = %+v hash=%q", got.Authority, got.AuthorityHash)
	}
	if len(got.Records) != 1 || got.Records[0].Key != "identity" || got.Records[0].HistoryCount != 1 {
		t.Fatalf("records = %+v", got.Records)
	}
	if got.Records[0].ValueJSON == nil || got.Records[0].RecordHash == "" || got.Records[0].Signature == "" {
		t.Fatalf("record should include parsed JSON, hash and signature: %+v", got.Records[0])
	}
	if len(got.RecordHistory) != 1 || got.HistoryCount != 1 {
		t.Fatalf("history = %+v count=%d", got.RecordHistory, got.HistoryCount)
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded["authority_hash"] == "" || decoded["history_count"] != float64(1) {
		t.Fatalf("decoded view missing stable fields: %#v", decoded)
	}
}

func TestBuildZoneDetailOmitsHistoryWhenDisabled(t *testing.T) {
	zs := zone.NewZoneState("node-a.catofes.", nil)
	zs.RecordHistory["identity"] = []*zone.Record{{Key: "identity", Version: 1}}

	got := BuildZoneDetail(ZoneDetailInput{
		Path:           "node-a.catofes.",
		State:          zs,
		IncludeHistory: false,
	})

	if len(got.RecordHistory) != 0 || got.HistoryCount != 1 {
		t.Fatalf("history = %+v count=%d", got.RecordHistory, got.HistoryCount)
	}
}
