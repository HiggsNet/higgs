package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func writeConfiguredPendingBootstrap(path string, config *appConfig) error {
	if err := validateAutoJoinBootstrapConfig(config); err != nil {
		return err
	}
	key, keyPath, err := configuredIdentityKey(config)
	if err != nil {
		return err
	}
	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: photoncrypto.SupportedThreshold,
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
	store, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		return err
	}
	defer store.Close()
	meta := stateMeta{
		ManagedZone:     config.ManagedZone,
		IdentityKeyPath: keyPath,
		ZonePrivateKey:  append(ed25519.PrivateKey(nil), key.PrivateKey...),
		SyncPeers:       make(map[string]syncPeerState),
	}
	return store.SaveNetworkAndMetaJSON(cliMetaKey, meta, ns)
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

func autoJoinPendingVerified(state *corestate.VerifiedState) bool {
	if state == nil || state.Network == nil || state.ManagedZone == "" || state.ManagedZone == zone.RootZone {
		return false
	}
	zs := state.Network.Zones[state.ManagedZone]
	if zs == nil || zs.Authority == nil {
		return true
	}
	if len(state.IdentityPrivateKey) != ed25519.PrivateKeySize {
		return true
	}
	pub := state.IdentityPrivateKey.Public().(ed25519.PublicKey)
	return !authorityHasKey(zs.Authority, pub)
}

func logAutoJoinPending(logger *appLogger, state *corestate.VerifiedState) {
	if !autoJoinPendingVerified(state) || len(state.IdentityPrivateKey) != ed25519.PrivateKeySize {
		return
	}
	pub := state.IdentityPrivateKey.Public().(ed25519.PublicKey)
	request, err := encodeBase64JSON(&joinRequest{Version: 1, Zone: state.ManagedZone, PublicKey: pub})
	if err != nil {
		return
	}
	if logger == nil {
		fmt.Fprintf(os.Stderr, "auto_join pending zone=%s join_request=%s hint=%q\n", state.ManagedZone, request, "photon gossip join request --from-config")
		return
	}
	logger.Info("auto_join", "pending", map[string]any{
		"zone":         state.ManagedZone,
		"join_request": request,
		"hint":         "photon gossip join request --from-config",
	})
}
