package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func createConfiguredBootstrapState(path string, config *appConfig) (*stateFile, error) {
	if err := validateAutoJoinBootstrapConfig(config); err != nil {
		return nil, err
	}
	key, keyPath, err := configuredIdentityKey(config)
	if err != nil {
		return nil, err
	}
	rootAuthority := configuredRootAuthority(config.TrustedRootPublicKey)
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	configureValidation(ns)
	state := &stateFile{
		ManagedZone:       config.ManagedZone,
		IdentityKeyPath:   keyPath,
		ZonePrivateKey:    append(ed25519.PrivateKey(nil), key.PrivateKey...),
		Network:           ns,
		SyncPeers:         make(map[string]syncPeerState),
		LinkInstances:     make(map[string]linkInstanceState),
		IPsecReconcile:    nil,
		IPsecPortRecord:   nil,
		IPsecTransportKey: nil,
	}
	if err := saveStateAt(path, state); err != nil {
		return nil, err
	}
	return state, nil
}

func validateAutoJoinBootstrapConfig(config *appConfig) error {
	if config == nil {
		return errors.New("cannot initialize empty state for auto-join: configuration is unavailable")
	}
	missing := make([]string, 0, 4)
	if config.ManagedZone == "" {
		missing = append(missing, "gossip.init.managed_zone")
	}
	if config.Identity.KeyPath == "" {
		missing = append(missing, "gossip.init.key_path")
	}
	if len(config.TrustedRootPublicKey) == 0 {
		missing = append(missing, "trusted_root_public_key")
	}
	if len(config.Bootstrap) == 0 {
		missing = append(missing, "gossip.bootstrap (at least one peer is required to synchronize the parent delegation)")
	}
	if len(missing) > 0 {
		return fmt.Errorf("cannot initialize empty state for auto-join: missing required configuration: %s", strings.Join(missing, ", "))
	}
	return nil
}

func applyConfiguredIdentityOverlay(state *stateFile, config *appConfig) error {
	if state == nil || config == nil {
		return nil
	}
	if config.ManagedZone == "" && config.Identity.KeyPath == "" {
		return nil
	}
	if state.ManagedZone == "" {
		return fmt.Errorf("configured identity requires initialized ManagedZone; use a new data_dir/state_path to create this node")
	}
	if config.ManagedZone != "" && state.ManagedZone != config.ManagedZone {
		return fmt.Errorf("managed_zone %s does not match DB ManagedZone %s; identity is immutable, use a new data_dir/state_path to create a different node", config.ManagedZone, state.ManagedZone)
	}
	if config.Identity.KeyPath == "" {
		return nil
	}
	key, keyPath, err := configuredIdentityKey(config)
	if err != nil {
		return err
	}
	if state.IdentityKeyPath != "" && state.IdentityKeyPath != keyPath {
		return fmt.Errorf("identity.key_path %s does not match DB identity key path %s; identity is immutable, use a new data_dir/state_path to create a different node", keyPath, state.IdentityKeyPath)
	}
	if len(state.ZonePrivateKey) == ed25519.PrivateKeySize {
		dbPub := state.ZonePrivateKey.Public().(ed25519.PublicKey)
		if !equalPublicKey(dbPub, key.PublicKey) {
			return fmt.Errorf("identity.key_path public key does not match DB ZonePrivateKey; identity is immutable, use a new data_dir/state_path to create a different node")
		}
	} else if len(state.ZonePrivateKey) != 0 {
		return errors.New("DB ZonePrivateKey is invalid")
	}
	if state.Network != nil {
		if zs := state.Network.Zones[state.ManagedZone]; zs != nil && zs.Authority != nil && !authorityHasKey(zs.Authority, key.PublicKey) {
			return fmt.Errorf("identity.key_path public key does not match ManagedZone authority for %s; identity is immutable, use a new data_dir/state_path to create a different node", state.ManagedZone)
		}
	}
	state.IdentityKeyPath = keyPath
	state.ZonePrivateKey = append(ed25519.PrivateKey(nil), key.PrivateKey...)
	return nil
}

func configuredIdentityKey(config *appConfig) (*privateKeyFile, string, error) {
	if config == nil || config.Identity.KeyPath == "" {
		return nil, "", errors.New("identity.key_path is required")
	}
	keyPath, err := canonicalIdentityKeyPath(config.Identity.KeyPath)
	if err != nil {
		return nil, "", err
	}
	key, err := readPrivateKeyFile(keyPath)
	if err != nil {
		return nil, "", err
	}
	return key, keyPath, nil
}

func canonicalIdentityKeyPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	clean := filepath.Clean(path)
	abs, err := filepath.Abs(clean)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func configuredJoinRequest(config *appConfig) (*joinRequest, error) {
	if config == nil || config.ManagedZone == "" {
		return nil, errors.New("managed_zone is required")
	}
	key, _, err := configuredIdentityKey(config)
	if err != nil {
		return nil, err
	}
	request := &joinRequest{
		Version:   1,
		Zone:      config.ManagedZone,
		PublicKey: key.PublicKey,
	}
	if err := validateJoinRequest(request); err != nil {
		return nil, err
	}
	return request, nil
}

func writeJoinRequestFromConfig(outPath string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	request, err := configuredJoinRequest(rt.Config)
	if err != nil {
		return err
	}
	if outPath == "" {
		text, err := encodeBase64JSON(request)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", text)
		return nil
	}
	if err := writeBase64JSONFile(outPath, 0o644, request); err != nil {
		return err
	}
	fmt.Printf("wrote join request: %s\n", outPath)
	return nil
}

func autoJoinPending(state *stateFile) bool {
	if state == nil || state.Network == nil || state.ManagedZone == "" || state.ManagedZone == zone.RootZone {
		return false
	}
	zs := state.Network.Zones[state.ManagedZone]
	if zs == nil || zs.Authority == nil {
		return true
	}
	if len(state.ZonePrivateKey) != ed25519.PrivateKeySize {
		return true
	}
	pub := state.ZonePrivateKey.Public().(ed25519.PublicKey)
	return !authorityHasKey(zs.Authority, pub)
}

func tryAdoptAutoJoinDelegation(state *stateFile, now time.Time) (bool, error) {
	if !autoJoinPending(state) || len(state.ZonePrivateKey) != ed25519.PrivateKeySize {
		return false, nil
	}
	if state.Network.Zones[state.ManagedZone] != nil {
		return false, nil
	}
	parent := state.ManagedZone.Parent()
	parentState := state.Network.Zones[parent]
	if parentState == nil || parentState.Authority == nil {
		return false, nil
	}
	delegation := parentState.Delegations[state.ManagedZone]
	if delegation == nil {
		return false, nil
	}
	pub := state.ZonePrivateKey.Public().(ed25519.PublicKey)
	if delegation.ZoneName != state.ManagedZone || delegation.Authority.Zone != state.ManagedZone || !authorityHasKey(&delegation.Authority, pub) {
		return false, nil
	}
	if err := photoncrypto.VerifyDelegation(delegation, parentState.Authority, parent, now); err != nil {
		return false, err
	}

	zs := zone.NewZoneState(state.ManagedZone, cloneAuthorityForJoinBundle(&delegation.Authority))
	zs.ParentProof = []*zone.Delegation{cloneDelegationForJoinBundle(delegation)}
	state.Network.Zones[state.ManagedZone] = zs
	configureValidation(state.Network)
	if err := photoncrypto.VerifyChain(state.Network, state.ManagedZone, now); err != nil {
		delete(state.Network.Zones, state.ManagedZone)
		return false, err
	}
	return true, nil
}

// tryRefreshManagedZoneAuthority applies a newer, parent-signed delegation to
// the local managed Zone without accepting a peer snapshot for that Zone. The
// parent owns the authority envelope; the local node continues to own its Zone
// contents (records, child delegations, revocations, and history).
func tryRefreshManagedZoneAuthority(state *stateFile, now time.Time) (bool, error) {
	if state == nil || state.Network == nil || state.ManagedZone == "" || state.ManagedZone == zone.RootZone {
		return false, nil
	}
	zs := state.Network.Zones[state.ManagedZone]
	if zs == nil || zs.Authority == nil {
		// First admission is handled by tryAdoptAutoJoinDelegation.
		return false, nil
	}

	parent := state.ManagedZone.Parent()
	parentState := state.Network.Zones[parent]
	if parentState == nil || parentState.Authority == nil {
		return false, nil
	}
	delegation := parentState.Delegations[state.ManagedZone]
	if delegation == nil {
		return false, nil
	}
	if delegation.ZoneName != state.ManagedZone || delegation.Authority.Zone != state.ManagedZone {
		return false, fmt.Errorf("managed zone delegation target mismatch: %s", state.ManagedZone)
	}
	if err := photoncrypto.VerifyChain(state.Network, parent, now); err != nil {
		return false, fmt.Errorf("verify managed zone parent %s: %w", parent, err)
	}
	if err := photoncrypto.VerifyDelegation(delegation, parentState.Authority, parent, now); err != nil {
		return false, err
	}

	currentEpoch := zs.Authority.Epoch
	nextEpoch := delegation.Authority.Epoch
	currentHash := photoncrypto.AuthorityHash(zs.Authority)
	nextHash := delegation.AuthorityHash
	switch {
	case nextEpoch < currentEpoch:
		return false, fmt.Errorf("managed zone delegation epoch %d is older than local authority epoch %d", nextEpoch, currentEpoch)
	case nextEpoch == currentEpoch && !bytes.Equal(nextHash, currentHash):
		return false, fmt.Errorf("managed zone authority conflicts at epoch %d", currentEpoch)
	case nextEpoch == currentEpoch:
		return false, nil
	}

	if len(state.ZonePrivateKey) != ed25519.PrivateKeySize {
		return false, errors.New("managed zone authority refresh requires a local zone private key")
	}
	pub := state.ZonePrivateKey.Public().(ed25519.PublicKey)
	if !authorityHasKey(&delegation.Authority, pub) {
		return false, errors.New("managed zone authority refresh does not authorize the local identity key")
	}

	previousAuthority := zs.Authority
	previousProof := zs.ParentProof
	zs.Authority = cloneAuthorityForJoinBundle(&delegation.Authority)
	zs.ParentProof = replaceDirectParentProof(previousProof, state.ManagedZone, delegation)
	configureValidation(state.Network)
	if err := photoncrypto.VerifyChain(state.Network, state.ManagedZone, now); err != nil {
		zs.Authority = previousAuthority
		zs.ParentProof = previousProof
		return false, err
	}
	return true, nil
}

func replaceDirectParentProof(existing []*zone.Delegation, managed zone.ZonePath, delegation *zone.Delegation) []*zone.Delegation {
	out := make([]*zone.Delegation, 0, len(existing)+1)
	out = append(out, cloneDelegationForJoinBundle(delegation))
	for _, proof := range existing {
		if proof == nil || proof.ZoneName == managed {
			continue
		}
		out = append(out, cloneDelegationForJoinBundle(proof))
	}
	return out
}

func logAutoJoinPendingProjection(logger *appLogger, projection autoJoinLogProjection) {
	if !projection.pending {
		return
	}
	if logger == nil {
		fmt.Fprintf(os.Stderr, "auto_join pending zone=%s join_request=%s hint=%q\n", projection.managedZone, projection.joinRequest, "photon gossip join request --from-config")
		return
	}
	logger.Info("auto_join", "pending", map[string]any{
		"zone":         projection.managedZone,
		"join_request": projection.joinRequest,
		"hint":         "photon gossip join request --from-config",
	})
}
