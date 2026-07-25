package text

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Catofes/higgs/internal/inspect"
)

func TestWriteZoneIsHumanReadableAndFiltersDelegations(t *testing.T) {
	view := inspect.ZoneDetail{
		Path:   "catofes.",
		Parent: ".",
		Authority: &inspect.AuthorityView{
			Epoch: 2, Threshold: 1,
			Keys: []inspect.AuthorizedKeyView{{Capabilities: []inspect.CapabilityView{{
				Permissions: []string{"write", "delegate"},
			}}}},
		},
		Delegations: []inspect.DelegationView{
			{
				Child: "node-a.catofes.", Scope: "direct-child", AuthorityEpoch: 3,
				AuthorityHash: "secret-hash", Signature: "secret-signature",
				Authority: &inspect.AuthorityView{Keys: []inspect.AuthorizedKeyView{{Capabilities: []inspect.CapabilityView{{
					Permissions: []string{"write"},
				}}}}},
			},
			{Child: "node-b.catofes."},
		},
	}
	var buf bytes.Buffer
	if err := WriteZone(&buf, view, "node-a", true); err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"zone: catofes.",
		"status: active",
		"permissions: delegate,write",
		"authority: epoch=2 keys=1 threshold=1",
		"delegations: 1/2",
		"node-a.catofes. permissions=write scope=direct-child epoch=3 expires=-",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
	for _, unwanted := range []string{"node-b.catofes.", "secret-hash", "secret-signature", `"path"`} {
		if strings.Contains(output, unwanted) {
			t.Fatalf("output unexpectedly contains %q:\n%s", unwanted, output)
		}
	}
}

func TestWriteZoneDebugPreservesLegacyLayout(t *testing.T) {
	view := inspect.ZoneDebugView{
		Detail: inspect.ZoneDetail{
			Path:            "node-a.catofes.",
			RecordCount:     1,
			HistoryCount:    2,
			DelegationCount: 3,
			RevocationCount: 4,
			ParentProof:     []inspect.DelegationView{{Child: "node-a.catofes."}},
			Records: []inspect.RecordView{{
				Key:     "identity",
				Version: 7,
				Type:    "profile",
			}},
		},
		RootHash:     "abcd",
		VerifyResult: "ok",
	}
	var buf bytes.Buffer
	if err := WriteZoneDebug(&buf, view); err != nil {
		t.Fatalf("WriteZoneDebug: %v", err)
	}
	for _, want := range []string{
		"zone: node-a.catofes.",
		"root: abcd",
		"records: 1",
		"history: 2",
		"delegations: 3",
		"revocations: 4",
		"parent_proof: 1",
		"revoked: false",
		"verify: ok",
		"record key=identity version=7 type=profile",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, buf.String())
		}
	}
}

func TestWriteZoneDebugRevocationFields(t *testing.T) {
	view := inspect.ZoneDebugView{
		Detail: inspect.ZoneDetail{Path: "node-a.catofes."},
		ActiveRevocation: &inspect.RevocationView{
			Parent:                "catofes.",
			Reason:                "rotated",
			RevokedAt:             100,
			RevokedAuthorityEpoch: 9,
		},
	}
	var buf bytes.Buffer
	if err := WriteZoneDebug(&buf, view); err != nil {
		t.Fatalf("WriteZoneDebug: %v", err)
	}
	for _, want := range []string{
		"revoked: true",
		"revoked_by: catofes.",
		"revoked_at: 1970-01-01T00:01:40Z",
		"revocation_reason: rotated",
		"revoked_authority_epoch: 9",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, buf.String())
		}
	}
}
