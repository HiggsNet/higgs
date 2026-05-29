package crypto

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
)

const (
	DomainRecord       = "higgs.record.v1"
	DomainDelegation   = "higgs.delegation.v1"
	DomainAuthority    = "higgs.authority.v1"
	DomainGossip       = "higgs.gossip.v1"
	SupportedThreshold = uint8(1)
)

var (
	ErrUnsupportedThreshold       = errors.New("unsupported threshold")
	ErrUnsupportedDelegationScope = errors.New("unsupported delegation scope")
)

func VerifyChain(ns *zone.NetworkState, zonePath zone.ZonePath, now time.Time) error {
	if ns == nil {
		return errors.New("network state is nil")
	}
	zs := ns.Zones[zonePath]
	if zs == nil {
		return errors.New("zone not found")
	}
	if !zonePath.Valid() {
		return errors.New("invalid zone path")
	}

	root := ns.Zones[zone.RootZone]
	if root == nil || root.Authority == nil {
		return errors.New("root authority is not trusted")
	}
	if err := verifyAuthoritySupported(root.Authority); err != nil {
		return err
	}
	if root.Authority.Zone != zone.RootZone {
		return errors.New("root authority zone mismatch")
	}

	for current := zonePath; current != zone.RootZone; current = current.Parent() {
		currentState := ns.Zones[current]
		if currentState == nil {
			return errors.New("zone not found")
		}
		if currentState.Authority == nil {
			return errors.New("zone authority is nil")
		}

		parent := current.Parent()
		parentState := ns.Zones[parent]
		if parentState == nil || parentState.Authority == nil {
			return errors.New("parent zone authority is nil")
		}

		delegation := parentState.Delegations[current]
		if delegation == nil {
			delegation = parentProofDelegation(currentState, current)
		}
		if delegation == nil {
			return errors.New("delegation not found")
		}
		if err := VerifyDelegation(delegation, parentState.Authority, parent, now); err != nil {
			return err
		}
		if !equalBytes(AuthorityHash(currentState.Authority), delegation.AuthorityHash) {
			return errors.New("zone authority does not match parent delegation")
		}
		if currentState.Authority.Epoch != delegation.AuthorityEpoch {
			return errors.New("zone authority epoch does not match parent delegation")
		}
	}

	return nil
}

func parentProofDelegation(zs *zone.ZoneState, zonePath zone.ZonePath) *zone.Delegation {
	if zs == nil {
		return nil
	}
	for _, proof := range zs.ParentProof {
		if proof != nil && proof.ZoneName == zonePath {
			return proof
		}
	}
	return nil
}

func SignRecord(r *zone.Record, priv ed25519.PrivateKey) error {
	if r == nil {
		return errors.New("record is nil")
	}
	pub := priv.Public().(ed25519.PublicKey)
	r.ValueHash = Hash(r.Value)
	r.SignedBy = append(r.SignedBy[:0], pub...)
	r.Signature = ed25519.Sign(priv, recordPayload(r))
	return nil
}

func VerifyRecord(r *zone.Record, authority *zone.ZoneAuthority, now time.Time) error {
	if r == nil {
		return errors.New("record is nil")
	}
	if err := verifyAuthoritySupported(authority); err != nil {
		return err
	}
	key, err := findAuthorizedKey(authority, r.SignedBy, zone.PermWrite, typePermission(r.Type), r.Key, now)
	if err != nil {
		return err
	}
	if !equalBytes(r.ValueHash, Hash(r.Value)) {
		return errors.New("record value hash mismatch")
	}
	if !ed25519.Verify(key.Key, recordPayload(r), r.Signature) {
		return errors.New("record signature invalid")
	}
	return nil
}

func SignDelegation(d *zone.Delegation, parent zone.ZonePath, priv ed25519.PrivateKey) error {
	if d == nil {
		return errors.New("delegation is nil")
	}
	d.Scope = normalizedDelegationScope(d)
	pub := priv.Public().(ed25519.PublicKey)
	d.AuthorityEpoch = d.Authority.Epoch
	d.AuthorityHash = AuthorityHash(&d.Authority)
	d.SignedBy = append(d.SignedBy[:0], pub...)
	d.Signature = ed25519.Sign(priv, delegationPayload(d, parent))
	return nil
}

func VerifyDelegation(d *zone.Delegation, parentAuthority *zone.ZoneAuthority, parentZone zone.ZonePath, now time.Time) error {
	if d == nil {
		return errors.New("delegation is nil")
	}
	if err := verifyAuthoritySupported(parentAuthority); err != nil {
		return err
	}
	switch normalizedDelegationScope(d) {
	case zone.DelegationScopeDirectChild:
		if d.ZoneName.Parent() != parentZone {
			return errors.New("delegation parent mismatch")
		}
	case zone.DelegationScopeSubtree:
		return ErrUnsupportedDelegationScope
	default:
		return ErrUnsupportedDelegationScope
	}
	key, err := findAuthorizedKey(parentAuthority, d.SignedBy, zone.PermDelegate, "", "", now)
	if err != nil {
		return err
	}
	if !equalBytes(d.AuthorityHash, AuthorityHash(&d.Authority)) {
		return errors.New("delegation authority hash mismatch")
	}
	if d.AuthorityEpoch != d.Authority.Epoch {
		return errors.New("delegation authority epoch mismatch")
	}
	if d.ExpiresAt != nil && !now.Before(*d.ExpiresAt) {
		return errors.New("delegation expired")
	}
	if !ed25519.Verify(key.Key, delegationPayload(d, parentZone), d.Signature) {
		return errors.New("delegation signature invalid")
	}
	return nil
}

func AuthorityHash(a *zone.ZoneAuthority) []byte {
	return Hash(authorityPayload(a))
}

func RecordHash(r *zone.Record) []byte {
	return Hash(recordPayload(r), r.Signature)
}

func recordPayload(r *zone.Record) []byte {
	var b builder
	b.str(DomainRecord)
	b.str(r.Zone.String())
	b.str(r.Key)
	b.str(r.Type)
	b.bytes(r.ValueHash)
	b.u64(r.Version)
	b.bytes(r.PrevHash)
	b.i64(r.Timestamp)
	b.bytes(KeyID(r.SignedBy))
	return b.out
}

func delegationPayload(d *zone.Delegation, parent zone.ZonePath) []byte {
	var b builder
	b.str(DomainDelegation)
	b.str(parent.String())
	b.str(d.ZoneName.String())
	b.str(string(normalizedDelegationScope(d)))
	b.u64(d.AuthorityEpoch)
	b.bytes(d.AuthorityHash)
	if d.ExpiresAt == nil {
		b.i64(0)
	} else {
		b.i64(d.ExpiresAt.Unix())
	}
	b.bytes(KeyID(d.SignedBy))
	return b.out
}

func normalizedDelegationScope(d *zone.Delegation) zone.DelegationScope {
	if d == nil || d.Scope == "" {
		return zone.DelegationScopeDirectChild
	}
	return d.Scope
}

func authorityPayload(a *zone.ZoneAuthority) []byte {
	if a == nil {
		return nil
	}
	var b builder
	b.str(DomainAuthority)
	b.str(a.Zone.String())
	b.u64(a.Epoch)
	b.u64(uint64(a.Threshold))
	b.u64(uint64(len(a.Keys)))
	for _, key := range a.Keys {
		b.bytes(key.Key)
		b.i64(key.NotBefore)
		b.i64(key.NotAfter)
		b.u64(uint64(len(key.Capabilities)))
		for _, cap := range key.Capabilities {
			b.str(cap.KeyPrefix)
			b.u64(uint64(len(cap.Permissions)))
			for _, perm := range cap.Permissions {
				b.str(string(perm))
			}
		}
	}
	return b.out
}

func verifyAuthoritySupported(a *zone.ZoneAuthority) error {
	if a == nil {
		return errors.New("authority is nil")
	}
	if a.Threshold != SupportedThreshold {
		return ErrUnsupportedThreshold
	}
	return nil
}

func findAuthorizedKey(a *zone.ZoneAuthority, signedBy ed25519.PublicKey, required zone.Permission, typed zone.Permission, key string, now time.Time) (*zone.AuthorizedKey, error) {
	for i := range a.Keys {
		candidate := &a.Keys[i]
		if !equalBytes(candidate.Key, signedBy) {
			continue
		}
		if candidate.NotBefore != 0 && now.Unix() < candidate.NotBefore {
			return nil, errors.New("authorized key not yet valid")
		}
		if candidate.NotAfter != 0 && now.Unix() > candidate.NotAfter {
			return nil, errors.New("authorized key expired")
		}
		if hasCapability(candidate.Capabilities, required, typed, key) {
			return candidate, nil
		}
		return nil, errors.New("authorized key lacks capability")
	}
	return nil, errors.New("signing key not authorized")
}

func hasCapability(caps []zone.Capability, required zone.Permission, typed zone.Permission, key string) bool {
	for _, cap := range caps {
		if cap.KeyPrefix != "" && !hasPrefix(key, cap.KeyPrefix) {
			continue
		}
		for _, perm := range cap.Permissions {
			if perm == required || (typed != "" && perm == typed) {
				return true
			}
		}
	}
	return false
}

func typePermission(recordType string) zone.Permission {
	switch recordType {
	case "wireguard.public_key", "wireguard.listen_port":
		return zone.PermWriteWireGuard
	case "route.announcement":
		return zone.PermWriteRoute
	default:
		return ""
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var out byte
	for i := range a {
		out |= a[i] ^ b[i]
	}
	return out == 0
}

type builder struct {
	out []byte
}

func (b *builder) str(s string) {
	b.bytes([]byte(s))
}

func (b *builder) bytes(v []byte) {
	var lenbuf [8]byte
	binary.BigEndian.PutUint64(lenbuf[:], uint64(len(v)))
	b.out = append(b.out, lenbuf[:]...)
	b.out = append(b.out, v...)
}

func (b *builder) u64(v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	b.out = append(b.out, buf[:]...)
}

func (b *builder) i64(v int64) {
	b.u64(uint64(v))
}
