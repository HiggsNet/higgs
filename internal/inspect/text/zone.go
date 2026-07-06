package text

import (
	"io"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
)

type ZoneDebugView struct {
	Detail           inspect.ZoneDetail
	RootHash         string
	VerifyResult     string
	ActiveRevocation *inspect.RevocationView
}

func WriteZoneDebug(w io.Writer, view ZoneDebugView) error {
	if w == nil {
		return nil
	}
	if view.VerifyResult == "" {
		view.VerifyResult = "ok"
	}
	out := newLineWriter(w)
	out.Linef("zone: %s", view.Detail.Path)
	lines := []struct {
		key   string
		value any
	}{
		{"root", view.RootHash},
		{"records", view.Detail.RecordCount},
		{"history", view.Detail.HistoryCount},
		{"delegations", view.Detail.DelegationCount},
		{"revocations", view.Detail.RevocationCount},
		{"parent_proof", len(view.Detail.ParentProof)},
	}
	for _, line := range lines {
		out.Linef("%s: %v", line.key, line.value)
	}
	if view.ActiveRevocation == nil {
		out.Println("revoked: false")
	} else {
		rev := view.ActiveRevocation
		revocationLines := []struct {
			key   string
			value any
		}{
			{"revoked", true},
			{"revoked_by", rev.Parent},
			{"revoked_at", formatUnixTime(rev.RevokedAt)},
			{"revocation_reason", dash(rev.Reason)},
			{"revoked_authority_epoch", rev.RevokedAuthorityEpoch},
		}
		for _, line := range revocationLines {
			out.Linef("%s: %v", line.key, line.value)
		}
	}
	out.Linef("verify: %s", view.VerifyResult)
	for _, record := range view.Detail.Records {
		out.Linef("record key=%s version=%d type=%s", record.Key, record.Version, record.Type)
	}
	return out.Err()
}

func formatUnixTime(unix int64) string {
	if unix == 0 {
		return "-"
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
