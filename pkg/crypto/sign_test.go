package crypto

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

func TestSignAndVerifyRecord(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	authority := &zone.ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWriteWireGuard},
				KeyPrefix:   "wireguard/",
			}},
		}},
	}

	record := &zone.Record{
		Zone:      "node1.catofes.",
		Key:       "wireguard/public_key",
		Type:      "wireguard.public_key",
		Value:     []byte("wg-pubkey"),
		Version:   1,
		Timestamp: 123,
	}

	if err := SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := VerifyRecord(record, authority, time.Unix(123, 0)); err != nil {
		t.Fatalf("VerifyRecord: %v", err)
	}

	record.Value = []byte("tampered")
	if err := VerifyRecord(record, authority, time.Unix(123, 0)); err == nil {
		t.Fatalf("VerifyRecord accepted tampered value")
	}
}

func TestVerifyRecordRejectsUnsupportedThreshold(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	record := &zone.Record{
		Zone:      "node1.catofes.",
		Key:       "identity",
		Type:      "node.identity",
		Value:     []byte("node1"),
		Version:   1,
		Timestamp: 123,
	}
	if err := SignRecord(record, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}

	err = VerifyRecord(record, &zone.ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 2,
		Keys: []zone.AuthorizedKey{{
			Key: pub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}, time.Unix(123, 0))
	if !errors.Is(err, ErrUnsupportedThreshold) {
		t.Fatalf("VerifyRecord error = %v, want ErrUnsupportedThreshold", err)
	}
}

func TestSignAndVerifyDelegation(t *testing.T) {
	parentPub, parentPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(parent): %v", err)
	}
	childPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(child): %v", err)
	}

	parentAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: parentPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}

	delegation := &zone.Delegation{
		ZoneName: "node1.catofes.",
		Scope:    zone.DelegationScopeDirectChild,
		Authority: zone.ZoneAuthority{
			Zone:      "node1.catofes.",
			Epoch:     1,
			Threshold: 1,
			Keys: []zone.AuthorizedKey{{
				Key: childPub,
				Capabilities: []zone.Capability{{
					Permissions: []zone.Permission{zone.PermWrite},
				}},
			}},
		},
	}

	if err := SignDelegation(delegation, "catofes.", parentPriv); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	if err := VerifyDelegation(delegation, parentAuthority, "catofes.", time.Unix(123, 0)); err != nil {
		t.Fatalf("VerifyDelegation: %v", err)
	}
}

func TestVerifyDelegationRejectsSubtreeScopeInPhase0(t *testing.T) {
	parentPub, parentPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(parent): %v", err)
	}
	childPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(child): %v", err)
	}

	parentAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: parentPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	delegation := &zone.Delegation{
		ZoneName: "node1.pek.catofes.",
		Scope:    zone.DelegationScopeSubtree,
		Authority: zone.ZoneAuthority{
			Zone:      "node1.pek.catofes.",
			Epoch:     1,
			Threshold: 1,
			Keys: []zone.AuthorizedKey{{
				Key: childPub,
				Capabilities: []zone.Capability{{
					Permissions: []zone.Permission{zone.PermWrite},
				}},
			}},
		},
	}

	if err := SignDelegation(delegation, "catofes.", parentPriv); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}
	err = VerifyDelegation(delegation, parentAuthority, "catofes.", time.Unix(123, 0))
	if !errors.Is(err, ErrUnsupportedDelegationScope) {
		t.Fatalf("VerifyDelegation error = %v, want ErrUnsupportedDelegationScope", err)
	}
}

func TestVerifyChain(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	childPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(child): %v", err)
	}

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	childAuthority := &zone.ZoneAuthority{
		Zone:      "catofes.",
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: childPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite},
			}},
		}},
	}
	delegation := &zone.Delegation{
		ZoneName:  "catofes.",
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *childAuthority,
	}
	if err := SignDelegation(delegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation: %v", err)
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", childAuthority)
	ns.Zones[zone.RootZone].Delegations["catofes."] = delegation

	if err := VerifyChain(ns, "catofes.", time.Unix(123, 0)); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}
