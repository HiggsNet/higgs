package text

import (
	"io"

	"github.com/Catofes/higgs/internal/inspect"
)

func WriteAdmissionDiagnosis(w io.Writer, d inspect.AdmissionDiagnosis) error {
	out := newLineWriter(w)
	out.Linef("managed_zone: %s", d.ManagedZone)
	out.Linef("parent_zone: %s", d.ParentZone)
	out.Linef("pending: %t", d.Pending)
	out.Linef("reason: %s", dash(d.Reason))
	out.LineIf(d.ReasonDetail != "", "reason_detail: %s", d.ReasonDetail)
	out.Linef("has_zone_private_key: %t", d.HasZonePrivateKey)
	out.Linef("parent_zone_known: %t", d.ParentZoneKnown)
	out.Linef("parent_authority_known: %t", d.ParentAuthorityKnown)
	out.Linef("delegation_known: %t", d.DelegationKnown)
	out.Linef("delegation_key_matches: %t", d.DelegationKeyMatches)
	out.Linef("pending_since: %s", formatUnixTime(d.PendingSinceUnix))
	out.Linef("adopted_at: %s", formatUnixTime(d.AdoptedAtUnix))
	out.Linef("last_bootstrap_sync: %s", formatUnixTime(d.LastBootstrapSyncUnix))
	out.LineIf(d.LastAdoptionError != "", "last_adoption_error: %s", d.LastAdoptionError)
	if d.JoinRequestB64 != "" {
		out.Linef("join_request: %s", d.JoinRequestB64)
		out.Linef("join_hint: %s", "higgs gossip delegate issue <join_request> (on parent zone admin)")
	}
	out.Linef("boundary: auto-join only completes identity materialization; TransportLink presence depends on local overlay/link group config, peer ipsec/* records, peer MeshPolicy and provider apply state")
	return out.Err()
}
