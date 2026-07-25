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

func TestBuildZoneDebugBuildsDetailAndDigest(t *testing.T) {
	zs := zone.NewZoneState("node-a.catofes.", nil)
	zs.Records["identity"] = &zone.Record{Zone: "node-a.catofes.", Key: "identity", Type: "profile", Value: []byte("node-a"), Version: 1}
	network := &zone.NetworkState{Zones: map[zone.ZonePath]*zone.ZoneState{"node-a.catofes.": zs}}
	network.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)

	got, ok := BuildZoneDebug(ZoneDebugInput{
		Network: network,
		Path:    "node-a.catofes.",
		Now:     time.Unix(100, 0),
	})

	if !ok {
		t.Fatalf("BuildZoneDebug returned ok=false")
	}
	if got.Detail.Path != "node-a.catofes." || got.Detail.RecordCount != 1 || got.RootHash == "" {
		t.Fatalf("zone debug view = %+v", got)
	}
	if got.VerifyResult == "" {
		t.Fatalf("verify result should be explicit: %+v", got)
	}
}

func TestBuildZoneDebugMissingZone(t *testing.T) {
	_, ok := BuildZoneDebug(ZoneDebugInput{
		Network: &zone.NetworkState{Zones: map[zone.ZonePath]*zone.ZoneState{}},
		Path:    "missing.catofes.",
		Now:     time.Unix(100, 0),
	})
	if ok {
		t.Fatalf("BuildZoneDebug missing zone returned ok=true")
	}
}

func TestBuildRecordDetailIncludesLimitedHistory(t *testing.T) {
	active := &zone.Record{
		Zone:    "node-a.catofes.",
		Key:     "site/name",
		Type:    "policy.json",
		Value:   []byte(`{"name":"active"}`),
		Version: 3,
	}
	old1 := &zone.Record{Zone: "node-a.catofes.", Key: "site/name", Type: "policy.json", Value: []byte(`{"name":"old-1"}`), Version: 1}
	old2 := &zone.Record{Zone: "node-a.catofes.", Key: "site/name", Type: "policy.json", Value: []byte(`{"name":"old-2"}`), Version: 2}

	got := BuildRecordDetail(active, []*zone.Record{old1, old2}, 1)

	if got.Key != "site/name" || got.Version != 3 || got.HistoryCount != 2 {
		t.Fatalf("record detail = %+v", got)
	}
	if got.ValueJSON == nil {
		t.Fatalf("record detail should parse JSON value: %+v", got)
	}
	if len(got.RecordHistory) != 1 || got.RecordHistory[0].Version != 2 {
		t.Fatalf("history = %+v, want latest limited history", got.RecordHistory)
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded["key"] != "site/name" || decoded["record_history"] == nil {
		t.Fatalf("decoded record detail missing flat JSON fields: %#v", decoded)
	}
}

func TestBuildRecordsDebugFiltersByPrefix(t *testing.T) {
	zs := zone.NewZoneState("node-a.catofes.", nil)
	zs.Records["ipsec/profile"] = &zone.Record{Zone: "node-a.catofes.", Key: "ipsec/profile", Type: "ipsec.profile.v1", Value: []byte(`{"enabled":true}`), Version: 1}
	zs.Records["ipsec/transport-key"] = &zone.Record{Zone: "node-a.catofes.", Key: "ipsec/transport-key", Type: "ipsec.transport_key.v1", Value: []byte("key"), Version: 1}
	zs.Records["sync/endpoint/udp"] = &zone.Record{Zone: "node-a.catofes.", Key: "sync/endpoint/udp", Type: "sync.endpoint", Value: []byte("endpoint"), Version: 1}
	network := &zone.NetworkState{Zones: map[zone.ZonePath]*zone.ZoneState{"node-a.catofes.": zs}}

	view := BuildRecordsDebug(RecordsDebugInput{
		Network: network,
		Path:    "node-a.catofes.",
		Prefix:  "ipsec/",
	})

	if view.ZoneCount != 1 || view.RecordCount != 2 || view.Prefix != "ipsec/" || len(view.Zones) != 1 {
		t.Fatalf("records debug view = %+v", view)
	}
	keys := map[string]bool{}
	for _, record := range view.Zones[0].Records {
		keys[record.Key] = true
		if record.Value == "" {
			t.Fatalf("record value should be retained for presenter: %+v", record)
		}
	}
	if !keys["ipsec/profile"] || !keys["ipsec/transport-key"] {
		t.Fatalf("missing expected ipsec records: %+v", view.Zones[0].Records)
	}
	if keys["sync/endpoint/udp"] {
		t.Fatalf("prefix leaked endpoint record: %+v", view.Zones[0].Records)
	}
}

func TestBuildRecordsDebugGroupsZonesByDotAndHyphenSuffix(t *testing.T) {
	network := zone.NewNetworkState()
	for _, path := range []zone.ZonePath{
		"a-sha.catofes.",
		"b-pek.catofes.",
		"a-pek.catofes.",
		"alpha.catofes.",
	} {
		zs := zone.NewZoneState(path, nil)
		zs.Records["identity"] = &zone.Record{Zone: path, Key: "identity"}
		network.Zones[path] = zs
	}
	view := BuildRecordsDebug(RecordsDebugInput{Network: network})
	want := []string{
		"alpha.catofes.",
		"a-pek.catofes.",
		"b-pek.catofes.",
		"a-sha.catofes.",
	}
	if len(view.Zones) != len(want) {
		t.Fatalf("zones = %+v, want %d", view.Zones, len(want))
	}
	for i, path := range want {
		if view.Zones[i].Path != path {
			t.Fatalf("zones[%d] = %q, want %q; all=%+v", i, view.Zones[i].Path, path, view.Zones)
		}
	}
}
