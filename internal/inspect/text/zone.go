package text

import (
	"fmt"
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
	if _, err := fmt.Fprintf(w, "zone: %s\n", view.Detail.Path); err != nil {
		return err
	}
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
		if _, err := fmt.Fprintf(w, "%s: %v\n", line.key, line.value); err != nil {
			return err
		}
	}
	if view.ActiveRevocation == nil {
		if _, err := fmt.Fprintln(w, "revoked: false"); err != nil {
			return err
		}
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
			if _, err := fmt.Fprintf(w, "%s: %v\n", line.key, line.value); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(w, "verify: %s\n", view.VerifyResult); err != nil {
		return err
	}
	for _, record := range view.Detail.Records {
		if _, err := fmt.Fprintf(w, "record key=%s version=%d type=%s\n", record.Key, record.Version, record.Type); err != nil {
			return err
		}
	}
	return nil
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
