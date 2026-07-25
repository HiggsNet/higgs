package text

import (
	"strings"
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
)

func TestWriteRecordsIsHumanReadableAndFilters(t *testing.T) {
	view := inspect.RecordsDebugView{
		ZoneCount:   1,
		RecordCount: 2,
		Zones: []inspect.RecordsDebugZoneView{{
			Path: "node-b.catofes.",
			Records: []inspect.RecordView{
				{
					Key: "identity", Type: "profile", Value: "node-b",
					Version: 2, Timestamp: 1700000000, HistoryCount: 1,
					RecordHash: "secret-hash", Signature: "secret-signature",
				},
				{Key: "sync/endpoint/udp", Type: "sync.endpoint", Value: "127.0.0.1:4242"},
			},
		}},
	}
	var output strings.Builder
	if err := WriteRecords(&output, view, "identity", true); err != nil {
		t.Fatalf("WriteRecords: %v", err)
	}
	for _, want := range []string{
		"zones: 1",
		"records: 1/2",
		"zone: node-b.catofes.",
		"identity",
		"type: profile",
		"value: node-b",
		"version: 2",
		"updated: 2023-11-14T22:13:20Z",
		"history: 1",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, output.String())
		}
	}
	for _, unwanted := range []string{"sync/endpoint/udp", "secret-hash", "secret-signature"} {
		if strings.Contains(output.String(), unwanted) {
			t.Fatalf("output unexpectedly contains %q:\n%s", unwanted, output.String())
		}
	}
}

func TestWriteRecordHidesDiagnosticFields(t *testing.T) {
	record := inspect.RecordDetailView{RecordView: inspect.RecordView{
		Zone: "node-b.catofes.", Key: "identity", Type: "profile", Value: "node-b",
		Version: 2, Timestamp: 1700000000, HistoryCount: 1,
		RecordHash: "secret-hash", Signature: "secret-signature",
	}}
	var output strings.Builder
	if err := WriteRecord(&output, record, true); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}
	for _, want := range []string{
		"record: node-b.catofes./identity",
		"type: profile",
		"value: node-b",
		"version: 2",
		"updated: 2023-11-14T22:13:20Z",
		"history: 1",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, output.String())
		}
	}
	for _, unwanted := range []string{"secret-hash", "secret-signature", `"record_hash"`} {
		if strings.Contains(output.String(), unwanted) {
			t.Fatalf("output unexpectedly contains %q:\n%s", unwanted, output.String())
		}
	}
}

func TestWriteRecordsDebug(t *testing.T) {
	view := inspect.RecordsDebugView{
		ZoneCount:   1,
		RecordCount: 1,
		Prefix:      "ipsec/",
		Zones: []inspect.RecordsDebugZoneView{{
			Path: "node-b.catofes.",
			Records: []inspect.RecordView{{
				Key:        "ipsec/profile",
				Version:    2,
				Type:       "ipsec.profile.v1",
				SignedBy:   "abcdef1234567890",
				Timestamp:  1700000000,
				RecordHash: "0123456789abcdef9999",
				Value:      `{"b":2,"a":1}`,
			}},
		}},
	}
	var buf strings.Builder
	if err := WriteRecordsDebug(&buf, view, true); err != nil {
		t.Fatalf("WriteRecordsDebug: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"zones: 1",
		"records: 1",
		"prefix: ipsec/",
		"zone node-b.catofes.",
		"record key=ipsec/profile version=2 type=ipsec.profile.v1 signed_by=abcdef123456... timestamp=2023-11-14T22:13:20Z hash=0123456789abcdef...",
		`value: {"a":1,"b":2}`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
