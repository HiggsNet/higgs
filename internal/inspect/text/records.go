package text

import (
	"encoding/json"
	"io"

	"github.com/Catofes/higgs/internal/inspect"
)

func WriteRecordsDebug(w io.Writer, view inspect.RecordsDebugView, values bool) error {
	out := newLineWriter(w)
	out.Linef("zones: %d", view.ZoneCount)
	out.Linef("records: %d", view.RecordCount)
	out.LineIf(view.Prefix != "", "prefix: %s", view.Prefix)
	for _, z := range view.Zones {
		out.Blank()
		out.Linef("zone %s", z.Path)
		out.Linef("  records: %d", len(z.Records))
		for _, record := range z.Records {
			out.Linef("  record key=%s version=%d type=%s signed_by=%s timestamp=%s hash=%s",
				record.Key,
				record.Version,
				dash(record.Type),
				shortText(record.SignedBy, 12),
				formatUnixTime(record.Timestamp),
				shortText(record.RecordHash, 16),
			)
			out.LineIf(values, "    value: %s", formatDebugRecordValue(record.Value))
		}
	}
	return out.Err()
}

func formatDebugRecordValue(value string) string {
	var decoded any
	if err := json.Unmarshal([]byte(value), &decoded); err == nil {
		if data, err := json.Marshal(decoded); err == nil {
			return string(data)
		}
	}
	return value
}
