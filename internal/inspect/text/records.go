package text

import (
	"encoding/json"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/Catofes/photon/internal/inspect"
)

// WriteRecords prints records for operators without exposing hashes, signing
// keys, or signatures. Those fields remain available through debug records.
func WriteRecords(w io.Writer, view inspect.RecordsDebugView, filter string, verbose bool) error {
	filter = strings.ToLower(strings.TrimSpace(filter))
	zones := make([]inspect.RecordsDebugZoneView, 0, len(view.Zones))
	recordCount := 0
	for _, zoneView := range view.Zones {
		filtered := inspect.RecordsDebugZoneView{Path: zoneView.Path}
		for _, record := range zoneView.Records {
			searchable := record.Key + " " + record.Type + " " + record.Value
			if filter == "" || strings.Contains(strings.ToLower(searchable), filter) {
				filtered.Records = append(filtered.Records, record)
			}
		}
		if len(filtered.Records) > 0 || (filter == "" && len(view.Zones) == 1) {
			recordCount += len(filtered.Records)
			zones = append(zones, filtered)
		}
	}

	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	out := newLineWriter(table)
	out.Linef("zones: %d", len(zones))
	out.Linef("records: %s", filteredCount(recordCount, view.RecordCount, filter))
	for _, zoneView := range zones {
		out.Blank()
		out.Linef("zone: %s", zoneView.Path)
		if verbose {
			out.Println("RECORD\tTYPE\tVALUE\tVERSION\tUPDATED\tHISTORY")
		} else {
			out.Println("RECORD\tTYPE\tVALUE")
		}
		for _, record := range zoneView.Records {
			if verbose {
				out.Linef("%s\t%s\t%s\t%d\t%s\t%d",
					record.Key,
					dash(record.Type),
					formatRecordTableValue(record.Value),
					record.Version,
					formatUnixTime(record.Timestamp),
					record.HistoryCount,
				)
			} else {
				out.Linef("%s\t%s\t%s",
					record.Key,
					dash(record.Type),
					formatRecordTableValue(record.Value),
				)
			}
		}
	}
	if err := out.Err(); err != nil {
		return err
	}
	return table.Flush()
}

func WriteRecord(w io.Writer, record inspect.RecordDetailView, verbose bool) error {
	out := newLineWriter(w)
	out.Linef("record: %s/%s", record.Zone, record.Key)
	out.Linef("type: %s", dash(record.Type))
	out.Linef("value: %s", formatDebugRecordValue(record.Value))
	if verbose {
		out.Linef("version: %d", record.Version)
		out.Linef("updated: %s", formatUnixTime(record.Timestamp))
		out.Linef("history: %d", record.HistoryCount)
	}
	return out.Err()
}

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

func formatRecordTableValue(value string) string {
	return escapeTableCell(formatDebugRecordValue(value))
}
