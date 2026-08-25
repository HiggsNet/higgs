package crypto

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestVerifyPinnedRoot(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, &zone.ZoneAuthority{
		Zone: zone.RootZone,
		Keys: []zone.AuthorizedKey{{Key: pub}},
	})
	if err := VerifyPinnedRoot(ns, pub); err != nil {
		t.Fatalf("VerifyPinnedRoot: %v", err)
	}
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPinnedRoot(ns, other); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong-root error = %v", err)
	}
}
