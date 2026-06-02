package gossip

import (
	"bytes"
	"testing"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestObjectPullRequestRoundTrip(t *testing.T) {
	req := &ObjectPullRequest{
		Type: ObjectPullZone,
		Zone: "catofes.",
	}
	data, err := EncodeObjectPullRequest(req)
	if err != nil {
		t.Fatalf("EncodeObjectPullRequest: %v", err)
	}
	if len(data) < 4 {
		t.Fatalf("data too short")
	}
	got, err := DecodeObjectPullRequest(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DecodeObjectPullRequest: %v", err)
	}
	if got.Type != ObjectPullZone || got.Zone != "catofes." {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestObjectPullResponseRoundTrip(t *testing.T) {
	resp := &ObjectPullResponse{
		OK: true,
		Snapshot: &ZoneSnapshot{
			Zone: "catofes.",
			Authority: &zone.ZoneAuthority{
				Zone:      "catofes.",
				Epoch:     1,
				Threshold: 1,
			},
		},
	}
	data, err := EncodeObjectPullResponse(resp)
	if err != nil {
		t.Fatalf("EncodeObjectPullResponse: %v", err)
	}
	got, err := DecodeObjectPullResponse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("DecodeObjectPullResponse: %v", err)
	}
	if !got.OK || got.Snapshot == nil || got.Snapshot.Zone != "catofes." {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestObjectPullRejectsOversizedPayload(t *testing.T) {
	// Encode a length prefix pointing to 2 MiB, but provide no payload.
	var sizeBuf [4]byte
	sizeBuf[0] = 0x00
	sizeBuf[1] = 0x20
	sizeBuf[2] = 0x00
	sizeBuf[3] = 0x00 // 2 MiB
	_, err := DecodeObjectPullRequest(bytes.NewReader(sizeBuf[:]))
	if err == nil {
		t.Fatalf("expected error for oversized payload")
	}
}
