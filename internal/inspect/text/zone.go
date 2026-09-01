package text

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
)

func WriteZones(w io.Writer, details []inspect.ZoneDetail, filter string, verbose bool) error {
	filter = strings.ToLower(strings.TrimSpace(filter))
	filtered := make([]inspect.ZoneDetail, 0, len(details))
	for _, detail := range details {
		status := "active"
		if detail.Revoked {
			status = "revoked"
		}
		searchable := strings.Join([]string{
			detail.Path,
			detail.Parent,
			status,
			authorityPermissions(detail.Authority),
		}, " ")
		if filter == "" || strings.Contains(strings.ToLower(searchable), filter) {
			filtered = append(filtered, detail)
		}
	}

	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	out := newLineWriter(table)
	out.Linef("zones: %s", filteredCount(len(filtered), len(details), filter))
	rows := make([][]string, 0, len(filtered)+1)
	if verbose {
		rows = append(rows, []string{"ZONE", "STATUS", "PARENT", "PERMISSIONS", "RECORDS", "HISTORY", "DELEGATIONS", "REVOCATIONS", "AUTHORITY"})
	} else {
		rows = append(rows, []string{"ZONE", "STATUS", "RECORDS", "DELEGATIONS"})
	}
	for _, detail := range filtered {
		status := "active"
		if detail.Revoked {
			status = "revoked"
		}
		if verbose {
			rows = append(rows, []string{
				detail.Path,
				status,
				dash(detail.Parent),
				authorityPermissions(detail.Authority),
				fmt.Sprint(detail.RecordCount),
				fmt.Sprint(detail.HistoryCount),
				fmt.Sprint(detail.DelegationCount),
				fmt.Sprint(detail.RevocationCount),
				zoneAuthoritySummary(detail.Authority),
			})
		} else {
			rows = append(rows, []string{
				detail.Path,
				status,
				fmt.Sprint(detail.RecordCount),
				fmt.Sprint(detail.DelegationCount),
			})
		}
	}
	if verbose {
		writeAlignedRows(out, rows, 0, 2)
	} else {
		writeAlignedRows(out, rows, 0)
	}
	if err := out.Err(); err != nil {
		return err
	}
	return table.Flush()
}

func zoneAuthoritySummary(authority *inspect.AuthorityView) string {
	if authority == nil {
		return "-"
	}
	return fmt.Sprintf("epoch=%d keys=%d threshold=%d", authority.Epoch, len(authority.Keys), authority.Threshold)
}

// WriteZone prints the operator-facing zone view. Cryptographic material is
// intentionally reserved for the debug commands.
func WriteZone(w io.Writer, detail inspect.ZoneDetail, filter string, verbose bool) error {
	out := newLineWriter(w)
	out.Linef("zone: %s", detail.Path)
	if detail.Revoked {
		out.Println("status: revoked")
	} else {
		out.Println("status: active")
	}
	out.Linef("permissions: %s", authorityPermissions(detail.Authority))
	if verbose {
		out.Linef("parent: %s", dash(detail.Parent))
		if detail.Authority == nil {
			out.Println("authority: -")
		} else {
			out.Linef("authority: epoch=%d keys=%d threshold=%d",
				detail.Authority.Epoch, len(detail.Authority.Keys), detail.Authority.Threshold)
		}
		out.Linef("parent proof: %d", len(detail.ParentProof))
	}

	delegations := filterDelegations(detail.Delegations, filter)
	out.Linef("delegations: %s", filteredCount(len(delegations), len(detail.Delegations), filter))
	for _, delegation := range delegations {
		out.Printf("  %s permissions=%s", delegation.Child, authorityPermissions(delegation.Authority))
		if verbose {
			out.Printf(" scope=%s epoch=%d expires=%s",
				dash(delegation.Scope),
				delegation.AuthorityEpoch,
				dash(delegation.ExpiresAt),
			)
		}
		out.Println()
	}

	revocations := filterRevocations(detail.Revocations, filter)
	out.Linef("revocations: %s", filteredCount(len(revocations), len(detail.Revocations), filter))
	for _, revocation := range revocations {
		out.Printf("  %s", revocation.Child)
		if verbose {
			out.Printf(" revoked_by=%s revoked_at=%s reason=%s",
				dash(revocation.Parent),
				formatUnixTime(revocation.RevokedAt),
				dash(revocation.Reason),
			)
		}
		out.Println()
	}
	return out.Err()
}

func WriteZoneDebug(w io.Writer, view inspect.ZoneInspectionView) error {
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

func authorityPermissions(authority *inspect.AuthorityView) string {
	if authority == nil {
		return "-"
	}
	seen := make(map[string]struct{})
	for _, key := range authority.Keys {
		for _, capability := range key.Capabilities {
			for _, permission := range capability.Permissions {
				seen[permission] = struct{}{}
			}
		}
	}
	permissions := make([]string, 0, len(seen))
	for permission := range seen {
		permissions = append(permissions, permission)
	}
	sort.Strings(permissions)
	if len(permissions) == 0 {
		return "-"
	}
	return strings.Join(permissions, ",")
}

func filterDelegations(items []inspect.DelegationView, filter string) []inspect.DelegationView {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" {
		return items
	}
	out := make([]inspect.DelegationView, 0, len(items))
	for _, item := range items {
		searchable := item.Child + " " + item.Scope + " " + authorityPermissions(item.Authority)
		if strings.Contains(strings.ToLower(searchable), filter) {
			out = append(out, item)
		}
	}
	return out
}

func filterRevocations(items []inspect.RevocationView, filter string) []inspect.RevocationView {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" {
		return items
	}
	out := make([]inspect.RevocationView, 0, len(items))
	for _, item := range items {
		searchable := item.Child + " " + item.Parent + " " + item.Reason
		if strings.Contains(strings.ToLower(searchable), filter) {
			out = append(out, item)
		}
	}
	return out
}

func filteredCount(visible, total int, filter string) string {
	if strings.TrimSpace(filter) == "" {
		return fmt.Sprintf("%d", total)
	}
	return fmt.Sprintf("%d/%d", visible, total)
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

func presentOrDash(ok bool) string {
	if ok {
		return "present"
	}
	return "-"
}

func formatUint32OrDash(value uint32) string {
	if value == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", value)
}
