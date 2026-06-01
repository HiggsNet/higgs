package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

type privateKeyFile struct {
	Type       string             `json:"type"`
	PublicKey  ed25519.PublicKey  `json:"public_key"`
	PrivateKey ed25519.PrivateKey `json:"private_key"`
}

type joinRequest struct {
	Version   uint8             `json:"version"`
	Zone      zone.ZonePath     `json:"zone"`
	PublicKey ed25519.PublicKey `json:"public_key"`
}

type joinBundle struct {
	Version       uint8              `json:"version"`
	Zone          zone.ZonePath      `json:"zone"`
	RootPublicKey ed25519.PublicKey  `json:"root_public_key"`
	Network       *zone.NetworkState `json:"network"`
}

func createJoinRequest(path zone.ZonePath, keyPath string, outPath string) error {
	if !path.Valid() || path == zone.RootZone {
		return fmt.Errorf("invalid join zone: %s", path)
	}
	key, err := readPrivateKeyFile(keyPath)
	if err != nil {
		return err
	}
	request := joinRequest{
		Version:   1,
		Zone:      path,
		PublicKey: key.PublicKey,
	}
	if err := writeJSONFile(outPath, 0o644, &request); err != nil {
		return err
	}
	fmt.Printf("wrote join request: %s\n", outPath)
	return nil
}

func issueDelegation(requestPath string, outPath string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	var request joinRequest
	if err := readJSONFile(requestPath, &request); err != nil {
		return err
	}
	if request.Version != 1 {
		return fmt.Errorf("unsupported join request version: %d", request.Version)
	}
	if !request.Zone.Valid() || request.Zone == zone.RootZone {
		return fmt.Errorf("invalid join zone: %s", request.Zone)
	}
	if len(request.PublicKey) != ed25519.PublicKeySize {
		return errors.New("join request public key is invalid")
	}
	parent := request.Zone.Parent()
	parentState := state.Network.Zones[parent]
	if parentState == nil || parentState.Authority == nil {
		return fmt.Errorf("%w: parent %s", zone.ErrZoneNotFound, parent)
	}
	signer, err := signerForParent(state, parent)
	if err != nil {
		return err
	}

	authorityEpoch := uint64(1)
	if parentState.Revocations != nil {
		if revocation := parentState.Revocations[request.Zone]; revocation != nil && revocation.RevokedAuthorityEpoch >= authorityEpoch {
			authorityEpoch = revocation.RevokedAuthorityEpoch + 1
		}
	}
	authority := &zone.ZoneAuthority{
		Zone:      request.Zone,
		Epoch:     authorityEpoch,
		Threshold: higgscrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: request.PublicKey,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate},
			}},
		}},
	}
	delegation := &zone.Delegation{
		ZoneName:  request.Zone,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *authority,
	}
	if err := higgscrypto.SignDelegation(delegation, parent, signer); err != nil {
		return err
	}
	parentState.Delegations[request.Zone] = delegation
	state.Network.Zones[request.Zone] = zone.NewZoneState(request.Zone, authority)
	configureValidation(state.Network)
	if err := higgscrypto.VerifyChain(state.Network, request.Zone, rt.Now()); err != nil {
		return err
	}
	if err := rt.SaveState(state); err != nil {
		return err
	}

	rootKey, err := rootPublicKey(state.Network)
	if err != nil {
		return err
	}
	bundle := joinBundle{
		Version:       1,
		Zone:          request.Zone,
		RootPublicKey: rootKey,
		Network:       cloneNetworkForBundle(state.Network),
	}
	if err := writeJSONFile(outPath, 0o644, &bundle); err != nil {
		return err
	}
	fmt.Printf("issued delegation for %s\n", request.Zone)
	fmt.Printf("wrote join bundle: %s\n", outPath)
	return nil
}

func revokeDelegation(path zone.ZonePath, reason string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	if !path.Valid() || path == zone.RootZone {
		return fmt.Errorf("invalid revoke zone: %s", path)
	}
	parent := path.Parent()
	parentState := state.Network.Zones[parent]
	if parentState == nil || parentState.Authority == nil {
		return fmt.Errorf("%w: parent %s", zone.ErrZoneNotFound, parent)
	}
	signer, err := signerForParent(state, parent)
	if err != nil {
		return err
	}
	if parentState.Revocations == nil {
		parentState.Revocations = make(map[zone.ZonePath]*zone.DelegationRevocation)
	}

	delegation := parentState.Delegations[path]
	authorityEpoch := uint64(1)
	var authorityHash []byte
	if delegation != nil {
		authorityEpoch = delegation.AuthorityEpoch
		authorityHash = append([]byte(nil), delegation.AuthorityHash...)
	} else if childState := state.Network.Zones[path]; childState != nil && childState.Authority != nil {
		authorityEpoch = childState.Authority.Epoch
		authorityHash = higgscrypto.AuthorityHash(childState.Authority)
	} else {
		return fmt.Errorf("delegation not found: %s", path)
	}
	if reason == "" {
		reason = "revoked"
	}
	revocation := &zone.DelegationRevocation{
		ChildZone:             path,
		ParentZone:            parent,
		RevokedAuthorityEpoch: authorityEpoch,
		RevokedAuthorityHash:  authorityHash,
		Reason:                reason,
		RevokedAt:             rt.Now().Unix(),
	}
	if err := higgscrypto.SignDelegationRevocation(revocation, parent, signer); err != nil {
		return err
	}
	if err := higgscrypto.VerifyDelegationRevocation(revocation, parentState.Authority, parent, rt.Now()); err != nil {
		return err
	}
	parentState.Revocations[path] = revocation
	delete(parentState.Delegations, path)
	cleanupRevokedPeerState(state, path)
	if err := rt.SaveState(state); err != nil {
		return err
	}
	fmt.Printf("revoked delegation for %s\n", path)
	return nil
}

func acceptJoinBundle(bundlePath string, keyPath string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	var bundle joinBundle
	if err := readJSONFile(bundlePath, &bundle); err != nil {
		return err
	}
	if bundle.Version != 1 {
		return fmt.Errorf("unsupported join bundle version: %d", bundle.Version)
	}
	if bundle.Network == nil {
		return errors.New("join bundle network is nil")
	}
	key, err := readPrivateKeyFile(keyPath)
	if err != nil {
		return err
	}
	zs := bundle.Network.Zones[bundle.Zone]
	if zs == nil || zs.Authority == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, bundle.Zone)
	}
	if !authorityHasKey(zs.Authority, key.PublicKey) {
		return errors.New("private key does not match delegated zone authority")
	}
	configureValidation(bundle.Network)
	normalizeState(bundle.Network)
	if err := higgscrypto.VerifyChain(bundle.Network, bundle.Zone, rt.Now()); err != nil {
		return err
	}
	state := &stateFile{
		ManagedZone:    bundle.Zone,
		ZonePrivateKey: key.PrivateKey,
		Network:        bundle.Network,
	}
	if err := rt.SaveState(state); err != nil {
		return err
	}
	path := rt.StatePath
	fmt.Printf("joined %s in %s\n", bundle.Zone, path)
	fmt.Printf("trusted root public key: %s\n", formatPublicKey(bundle.RootPublicKey))
	return nil
}

func cleanupRevokedPeerState(state *stateFile, revoked zone.ZonePath) {
	if state == nil || len(state.SyncPeers) == 0 {
		return
	}
	for peerID := range state.SyncPeers {
		path := zone.ZonePath(peerID)
		if path == revoked || isZoneDescendantOf(path, revoked) {
			delete(state.SyncPeers, peerID)
		}
	}
}

func isZoneDescendantOf(path, parent zone.ZonePath) bool {
	if !path.Valid() || !parent.Valid() || path == parent {
		return false
	}
	for current := path.Parent(); current != zone.RootZone; current = current.Parent() {
		if current == parent {
			return true
		}
	}
	return parent == zone.RootZone
}

func signerForParent(state *stateFile, parent zone.ZonePath) (ed25519.PrivateKey, error) {
	switch {
	case parent == zone.RootZone:
		if len(state.RootPrivateKey) == ed25519.PrivateKeySize {
			return state.RootPrivateKey, nil
		}
	case parent == state.ManagedZone && len(state.ZonePrivateKey) == ed25519.PrivateKeySize:
		return state.ZonePrivateKey, nil
	}
	return nil, fmt.Errorf("no local signing key for parent zone %s", parent)
}

func rootPublicKey(ns *zone.NetworkState) (ed25519.PublicKey, error) {
	root := ns.Zones[zone.RootZone]
	if root == nil || root.Authority == nil || len(root.Authority.Keys) == 0 {
		return nil, errors.New("root authority has no public key")
	}
	return root.Authority.Keys[0].Key, nil
}

func authorityHasKey(authority *zone.ZoneAuthority, pub ed25519.PublicKey) bool {
	for _, key := range authority.Keys {
		if equalPublicKey(key.Key, pub) {
			return true
		}
	}
	return false
}

func readPrivateKeyFile(path string) (*privateKeyFile, error) {
	var key privateKeyFile
	if err := readJSONFile(path, &key); err != nil {
		return nil, err
	}
	if key.Type != "higgs.ed25519.private.v1" {
		return nil, errors.New("unsupported key file type")
	}
	if len(key.PrivateKey) != ed25519.PrivateKeySize || len(key.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid ed25519 key file")
	}
	derived := key.PrivateKey.Public().(ed25519.PublicKey)
	if !equalPublicKey(derived, key.PublicKey) {
		return nil, errors.New("private key does not match public key")
	}
	return &key, nil
}

func cloneNetworkForBundle(ns *zone.NetworkState) *zone.NetworkState {
	data, err := json.Marshal(ns)
	if err != nil {
		panic(err)
	}
	var out zone.NetworkState
	if err := json.Unmarshal(data, &out); err != nil {
		panic(err)
	}
	normalizeState(&out)
	return &out
}
