package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

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

func runRoot(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "init":
		managedZone := zone.ZonePath("local.")
		if len(args) > 1 {
			managedZone = zone.ZonePath(args[1])
		}
		return initState(managedZone)
	case "pubkey":
		state, err := loadState()
		if err != nil {
			return err
		}
		root := state.Network.Zones[zone.RootZone]
		if root == nil || root.Authority == nil || len(root.Authority.Keys) == 0 {
			return errors.New("root authority has no public key")
		}
		fmt.Println(hex.EncodeToString(root.Authority.Keys[0].Key))
		return nil
	default:
		return usage()
	}
}

func keygen(path string) error {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	key := privateKeyFile{
		Type:       "higgs.ed25519.private.v1",
		PublicKey:  pub,
		PrivateKey: priv,
	}
	if err := writeJSONFile(path, 0o600, &key); err != nil {
		return err
	}
	fmt.Printf("wrote key: %s\n", path)
	fmt.Printf("public key: %s\n", hex.EncodeToString(pub))
	return nil
}

func runJoin(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "request":
		if len(args) != 4 {
			return usage()
		}
		return createJoinRequest(zone.ZonePath(args[1]), args[2], args[3])
	case "accept":
		if len(args) != 3 {
			return usage()
		}
		return acceptJoinBundle(args[1], args[2])
	default:
		return usage()
	}
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

func runDelegate(args []string) error {
	if len(args) != 3 || args[0] != "issue" {
		return usage()
	}
	return issueDelegation(args[1], args[2])
}

func issueDelegation(requestPath string, outPath string) error {
	state, err := loadState()
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

	authority := &zone.ZoneAuthority{
		Zone:      request.Zone,
		Epoch:     1,
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
	if err := higgscrypto.VerifyChain(state.Network, request.Zone, time.Now()); err != nil {
		return err
	}
	if err := saveState(state); err != nil {
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

func acceptJoinBundle(bundlePath string, keyPath string) error {
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
	if err := higgscrypto.VerifyChain(bundle.Network, bundle.Zone, time.Now()); err != nil {
		return err
	}
	state := &stateFile{
		ManagedZone:    bundle.Zone,
		ZonePrivateKey: key.PrivateKey,
		Network:        bundle.Network,
	}
	if err := saveState(state); err != nil {
		return err
	}
	path, err := configuredStatePath()
	if err != nil {
		return err
	}
	fmt.Printf("joined %s in %s\n", bundle.Zone, path)
	fmt.Printf("trusted root public key: %s\n", hex.EncodeToString(bundle.RootPublicKey))
	return nil
}

func signerForParent(state *stateFile, parent zone.ZonePath) (ed25519.PrivateKey, error) {
	switch {
	case parent == zone.RootZone:
		if len(state.RootPrivateKey) == ed25519.PrivateKeySize {
			return state.RootPrivateKey, nil
		}
	case len(state.ZonePrivateKey) == ed25519.PrivateKeySize:
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

func readJSONFile(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func writeJSONFile(path string, mode os.FileMode, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, mode)
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
