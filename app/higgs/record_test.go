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

	record, err := lookupRecordJSON(state, managed, "site/name")
	if err != nil {
		t.Fatalf("lookupRecordJSON: %v", err)
	}
	if record["zone"] != string(managed) || record["key"] != "site/name" || record["type"] != "policy.json" {
		t.Fatalf("record JSON = %#v", record)
	}
	if record["value"] != `{"name":"pek"}` || record["value_json"] == nil || record["record_hash"] == "" {
		t.Fatalf("record JSON missing value fields: %#v", record)
	}

	if _, err := lookupRecordJSON(state, managed, "missing"); err == nil {
		t.Fatal("lookupRecordJSON missing record error = nil")
	}
	if _, err := lookupRecordJSON(state, zone.ZonePath("missing."), "site/name"); err == nil {
		t.Fatal("lookupRecordJSON missing zone error = nil")
	}
}
