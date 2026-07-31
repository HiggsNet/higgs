package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func createConfiguredBootstrapState(path string, config *appConfig) (*stateFile, error) {
	if config == nil || config.ManagedZone == "" || config.Identity.KeyPath == "" || len(config.TrustedRootPublicKey) == 0 || len(config.Bootstrap) == 0 {
		return nil, errors.New("state file has no network")
	}
	key, keyPath, err := configuredIdentityKey(config)
	if err != nil {
		return nil, err
	}
	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: higgscrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key: append(ed25519.PublicKey(nil), config.TrustedRootPublicKey...),
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate, zone.PermWrite},
			}},
		}},
	}
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
	if err := higgscrypto.VerifyDelegation(delegation, parentState.Authority, parent, now); err != nil {
		return false, err
	}

	zs := zone.NewZoneState(state.ManagedZone, cloneAuthorityForJoinBundle(&delegation.Authority))
	zs.ParentProof = []*zone.Delegation{cloneDelegationForJoinBundle(delegation)}
	state.Network.Zones[state.ManagedZone] = zs
	configureValidation(state.Network)
	if err := higgscrypto.VerifyChain(state.Network, state.ManagedZone, now); err != nil {
		delete(state.Network.Zones, state.ManagedZone)
		return false, err
	}
	return true, nil
}

func logAutoJoinPending(logger *appLogger, state *stateFile) {
	if !autoJoinPending(state) || len(state.ZonePrivateKey) != ed25519.PrivateKeySize {
		return
	}
	pub := state.ZonePrivateKey.Public().(ed25519.PublicKey)
	request := joinRequest{Version: 1, Zone: state.ManagedZone, PublicKey: pub}
	text, err := encodeBase64JSON(&request)
	if err != nil {
		return
	}
	if logger == nil {
		fmt.Fprintf(os.Stderr, "auto_join pending zone=%s join_request=%s hint=%q\n", state.ManagedZone, text, "higgs gossip join request --from-config")
		return
	}
	logger.Info("auto_join", "pending", map[string]any{
		"zone":         state.ManagedZone,
		"join_request": text,
		"hint":         "higgs gossip join request --from-config",
	})
}

func logAutoJoinPendingProjection(logger *appLogger, projection autoJoinLogProjection) {
	if !projection.pending {
		return
	}
	if logger == nil {
		fmt.Fprintf(os.Stderr, "auto_join pending zone=%s join_request=%s hint=%q\n", projection.managedZone, projection.joinRequest, "higgs gossip join request --from-config")
		return
	}
	logger.Info("auto_join", "pending", map[string]any{
		"zone":         projection.managedZone,
		"join_request": projection.joinRequest,
		"hint":         "higgs gossip join request --from-config",
	})
}
