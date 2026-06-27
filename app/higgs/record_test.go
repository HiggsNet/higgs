package main

import (
	"testing"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestLookupRecordJSON(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)
	if err := putRecordDirect(rt, managed, "site/name", []byte(`{"name":"pek"}`), "policy.json"); err != nil {
		t.Fatalf("putRecordDirect: %v", err)
	}
	state, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	record, err := lookupRecordJSON(state, managed, "site/name", 0)
	if err != nil {
		t.Fatalf("lookupRecordJSON: %v", err)
	}
	if record["zone"] != string(managed) || record["key"] != "site/name" || record["type"] != "policy.json" {
		t.Fatalf("record JSON = %#v", record)
	}
	if record["value"] != `{"name":"pek"}` || record["value_json"] == nil || record["record_hash"] == "" {
		t.Fatalf("record JSON missing value fields: %#v", record)
	}
	if _, ok := record["record_history"]; ok {
		t.Fatalf("record_history should be omitted by default: %#v", record)
	}

	if err := putRecordDirect(rt, managed, "site/name", []byte(`{"name":"pek-2"}`), "policy.json"); err != nil {
		t.Fatalf("putRecordDirect second version: %v", err)
	}
	if err := putRecordDirect(rt, managed, "site/name", []byte(`{"name":"pek-3"}`), "policy.json"); err != nil {
		t.Fatalf("putRecordDirect third version: %v", err)
	}
	state, err = rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState after history writes: %v", err)
	}
	record, err = lookupRecordJSON(state, managed, "site/name", 2)
	if err != nil {
		t.Fatalf("lookupRecordJSON with history: %v", err)
	}
	history := record["record_history"].([]map[string]any)
	if len(history) != 2 {
		t.Fatalf("history len = %d, want 2", len(history))
	}
	if history[0]["version"] != uint64(2) || history[1]["version"] != uint64(1) {
		t.Fatalf("history versions = %#v, want latest history first", history)
	}

	if _, err := lookupRecordJSON(state, managed, "missing", 0); err == nil {
		t.Fatal("lookupRecordJSON missing record error = nil")
	}
	if _, err := lookupRecordJSON(state, zone.ZonePath("missing."), "site/name", 0); err == nil {
		t.Fatal("lookupRecordJSON missing zone error = nil")
	}
	if _, err := lookupRecordJSON(state, managed, "site/name", -1); err == nil {
		t.Fatal("lookupRecordJSON negative history error = nil")
	}
}
