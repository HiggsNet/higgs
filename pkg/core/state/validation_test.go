package state

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestValidateStateRootChecksPinAndRequiredShape(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, &zone.ZoneAuthority{
		Zone: zone.RootZone, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: rootPublic}},
	})
	valid := &VerifiedState{
		ManagedZone: zone.RootZone, Network: network, TrustedRootPublicKey: rootPublic, RootPrivateKey: rootPrivate,
	}
	if err := ValidateStateRoot(valid); err != nil {
		t.Fatalf("ValidateStateRoot(valid): %v", err)
	}

	otherPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(other): %v", err)
	}
	tests := []struct {
		name  string
		state *VerifiedState
	}{
		{name: "nil"},
		{name: "network missing", state: &VerifiedState{ManagedZone: zone.RootZone}},
		{name: "managed zone missing", state: &VerifiedState{ManagedZone: "node.catofes.", Network: network}},
		{name: "bad root private key", state: &VerifiedState{ManagedZone: zone.RootZone, Network: network, RootPrivateKey: []byte("short")}},
		{name: "bad identity private key", state: &VerifiedState{ManagedZone: zone.RootZone, Network: network, IdentityPrivateKey: []byte("short")}},
		{name: "wrong root pin", state: &VerifiedState{ManagedZone: zone.RootZone, Network: network, TrustedRootPublicKey: otherPublic}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateStateRoot(test.state); !errors.Is(err, ErrInvalidStateRoot) {
				t.Fatalf("error = %v, want ErrInvalidStateRoot", err)
			}
		})
	}
}
