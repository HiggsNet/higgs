package text

import (
	"strings"
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
)

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
