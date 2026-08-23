package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
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

type delegationIssueResult struct {
	Zone   zone.ZonePath
	Bundle *joinBundle
}

type joinAcceptResult struct {
	Zone          zone.ZonePath
	RootPublicKey ed25519.PublicKey
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
	if outPath == "" {
		text, err := encodeBase64JSON(&request)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", text)
		return nil
	}
	if err := writeBase64JSONFile(outPath, 0o644, &request); err != nil {
		return err
	}
	fmt.Printf("wrote join request: %s\n", outPath)
	return nil
}

func issueDelegation(requestInput string, outPath string, permissions []zone.Permission, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	var request joinRequest
	if err := readBase64JSONOrJSON(requestInput, &request); err != nil {
		return err
	}
	if err := validateJoinRequest(&request); err != nil {
		return err
	}
	bundle, controlled, err := issueDelegationViaControl(rt, &request, permissions)
	if err != nil {
		return err
	}
	if controlled {
		if outPath == "" {
			fmt.Fprintf(os.Stderr, "issued delegation for %s via daemon\n", request.Zone)
			text, err := encodeBase64JSON(bundle)
			if err != nil {
				return err
			}
			fmt.Printf("%s\n", text)
			return nil
		}
		fmt.Printf("issued delegation for %s via daemon\n", request.Zone)
		if err := writeBase64JSONFile(outPath, 0o644, bundle); err != nil {
			return err
		}
		fmt.Printf("wrote join bundle: %s\n", outPath)
		return nil
	}
	if !direct {
		logControlFallback("delegate_issue")
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	result, err := issueDelegationInState(rt, state, &request, permissions)
	if err != nil {
		return err
	}
	if err := rt.SaveState(state); err != nil {
		return err
	}
	if outPath == "" {
		fmt.Fprintf(os.Stderr, "issued delegation for %s\n", request.Zone)
		text, err := encodeBase64JSON(result.Bundle)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", text)
		return nil
	}
	fmt.Printf("issued delegation for %s\n", request.Zone)
	if err := writeBase64JSONFile(outPath, 0o644, result.Bundle); err != nil {
		return err
	}
	fmt.Printf("wrote join bundle: %s\n", outPath)
	return nil
}

func issueDelegationInState(rt *Runtime, state *stateFile, request *joinRequest, permissions []zone.Permission) (*delegationIssueResult, error) {
	if err := validateJoinRequest(request); err != nil {
		return nil, err
	}
	parent := request.Zone.Parent()
	parentState := state.Network.Zones[parent]
	if parentState == nil || parentState.Authority == nil {
		return nil, fmt.Errorf("%w: parent %s", zone.ErrZoneNotFound, parent)
	}
	signer, err := signerForParent(state, parent)
	if err != nil {
		return nil, err
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
		Threshold: photoncrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{
			Key:          request.PublicKey,
			Capabilities: delegationCapabilities(permissions),
		}},
	}
	delegation := &zone.Delegation{
		ZoneName:  request.Zone,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *authority,
	}
	if err := photoncrypto.SignDelegation(delegation, parent, signer); err != nil {
		return nil, err
	}
	parentState.Delegations[request.Zone] = delegation
	state.Network.Zones[request.Zone] = zone.NewZoneState(request.Zone, authority)
	configureValidation(state.Network)
	if err := photoncrypto.VerifyChain(state.Network, request.Zone, rt.Now()); err != nil {
		return nil, err
	}

	rootKey, err := rootPublicKey(state.Network)
	if err != nil {
		return nil, err
	}
	bundleNetwork, err := minimalNetworkForJoinBundle(state.Network, request.Zone)
	if err != nil {
		return nil, err
	}
	configureValidation(bundleNetwork)
	if err := photoncrypto.VerifyChain(bundleNetwork, request.Zone, rt.Now()); err != nil {
		return nil, err
	}
	bundle := joinBundle{
		Version:       1,
		Zone:          request.Zone,
		RootPublicKey: rootKey,
		Network:       bundleNetwork,
	}
	return &delegationIssueResult{Zone: request.Zone, Bundle: &bundle}, nil
}

func delegationCapabilities(permissions []zone.Permission) []zone.Capability {
	if len(permissions) == 0 {
		return defaultDelegationCapabilities()
	}
	out := append([]zone.Permission(nil), permissions...)
	slices.Sort(out)
	return []zone.Capability{{Permissions: out}}
}

func revokeDelegation(path zone.ZonePath, reason string, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	controlled, err := revokeDelegationViaControl(rt, path, reason)
	if err != nil {
		return err
	}
	if controlled {
		fmt.Printf("revoked delegation for %s via daemon\n", path)
		return nil
	}
	if !direct {
		logControlFallback("delegate_revoke")
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	if err := revokeDelegationInState(rt, state, path, reason); err != nil {
		return err
	}
	if err := rt.SaveState(state); err != nil {
		return err
	}
	fmt.Printf("revoked delegation for %s\n", path)
	return nil
}

func revokeDelegationInState(rt *Runtime, state *stateFile, path zone.ZonePath, reason string) error {
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
		authorityHash = photoncrypto.AuthorityHash(childState.Authority)
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
	if err := photoncrypto.SignDelegationRevocation(revocation, parent, signer); err != nil {
		return err
	}
	if err := photoncrypto.VerifyDelegationRevocation(revocation, parentState.Authority, parent, rt.Now()); err != nil {
		return err
	}
	parentState.Revocations[path] = revocation
	delete(parentState.Delegations, path)
	cleanupRevokedPeerState(state, path)
	return nil
}

func acceptJoinBundle(bundleInput string, keyPath string, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	var bundle joinBundle
	if err := readBase64JSONOrJSON(bundleInput, &bundle); err != nil {
		return err
	}
	key, err := optionalJoinAcceptKey(rt, keyPath)
	if err != nil {
		return err
	}
	controlled, err := acceptJoinBundleViaControl(rt, &bundle, key)
	if err != nil {
		return err
	}
	if controlled {
		fmt.Printf("joined %s via daemon in %s\n", bundle.Zone, rt.StatePath)
		fmt.Printf("trusted root public key: %s\n", formatPublicKey(bundle.RootPublicKey))
		return nil
	}
	if !direct {
		logControlFallback("join_accept")
	}
	result, err := acceptJoinBundleInState(rt, &bundle, key)
	if err != nil {
		return err
	}
	fmt.Printf("joined %s in %s\n", result.Zone, rt.StatePath)
	fmt.Printf("trusted root public key: %s\n", formatPublicKey(result.RootPublicKey))
	return nil
}

func acceptJoinBundleInState(rt *Runtime, bundle *joinBundle, key *privateKeyFile) (*joinAcceptResult, error) {
	var existing *stateFile
	if loaded, err := rt.LoadState(); err == nil {
		existing = loaded
	}
	state, result, err := prepareJoinAcceptedState(rt, existing, bundle, key)
	if err != nil {
		return nil, err
	}
	if err := rt.SaveState(state); err != nil {
		return nil, err
	}
	return result, nil
}

func prepareJoinAcceptedState(rt *Runtime, existing *stateFile, bundle *joinBundle, key *privateKeyFile) (*stateFile, *joinAcceptResult, error) {
	if rt == nil {
		return nil, nil, errors.New("runtime is nil")
	}
	if bundle == nil {
		return nil, nil, errors.New("join bundle is nil")
	}
	if bundle.Version != 1 {
		return nil, nil, fmt.Errorf("unsupported join bundle version: %d", bundle.Version)
	}
	if bundle.Network == nil {
		return nil, nil, errors.New("join bundle network is nil")
	}
	if key == nil {
		var err error
		key, err = joinAcceptKeyFromStateFile(existing, bundle.Zone)
		if err != nil {
			return nil, nil, err
		}
	}
	if err := validatePrivateKeyFile(key); err != nil {
		return nil, nil, err
	}
	zs := bundle.Network.Zones[bundle.Zone]
	if zs == nil || zs.Authority == nil {
		return nil, nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, bundle.Zone)
	}
	if !authorityHasKey(zs.Authority, key.PublicKey) {
		return nil, nil, errors.New("private key does not match delegated zone authority")
	}
	bundleNetwork := zone.CloneNetworkState(bundle.Network)
	configureValidation(bundleNetwork)
	normalizeState(bundleNetwork)
	if err := photoncrypto.VerifyChain(bundleNetwork, bundle.Zone, rt.Now()); err != nil {
		return nil, nil, err
	}
	state := &stateFile{
		ManagedZone:    bundle.Zone,
		ZonePrivateKey: append([]byte(nil), key.PrivateKey...),
		Network:        bundleNetwork,
	}
	if existing != nil && existing.ManagedZone == bundle.Zone {
		state = cloneStateFile(existing)
		state.ManagedZone = bundle.Zone
		state.ZonePrivateKey = append([]byte(nil), key.PrivateKey...)
		if state.Network == nil {
			state.Network = zone.NewNetworkState()
		}
		mergeJoinBundleNetwork(state.Network, bundleNetwork)
		configureValidation(state.Network)
		normalizeState(state.Network)
		if err := photoncrypto.VerifyChain(state.Network, bundle.Zone, rt.Now()); err != nil {
			return nil, nil, err
		}
	}
	return state, &joinAcceptResult{Zone: bundle.Zone, RootPublicKey: append([]byte(nil), bundle.RootPublicKey...)}, nil
}

func installPreparedState(dst, src *stateFile) {
	if dst == nil || src == nil {
		return
	}
	dst.ManagedZone = src.ManagedZone
	dst.IdentityKeyPath = src.IdentityKeyPath
	dst.RootPrivateKey = src.RootPrivateKey
	dst.ZonePrivateKey = src.ZonePrivateKey
	dst.Network = src.Network
	dst.SyncPeers = src.SyncPeers
	dst.PeerCleanups = src.PeerCleanups
	dst.IPsecTransportKey = src.IPsecTransportKey
	dst.IPsecPortRecord = src.IPsecPortRecord
	dst.LinkInstances = src.LinkInstances
	dst.IPsecReconcile = src.IPsecReconcile
	dst.RoutingReconcile = src.RoutingReconcile
	dst.FirewallReconcile = src.FirewallReconcile
	dst.EndpointACLs = src.EndpointACLs
	dst.BirdInstances = src.BirdInstances
	dst.Admission = src.Admission
}

func optionalJoinAcceptKey(_ *Runtime, keyPath string) (*privateKeyFile, error) {
	if keyPath != "" {
		return readPrivateKeyFile(keyPath)
	}
	return nil, nil
}

func joinAcceptKeyFromStateFile(state *stateFile, expectedZone zone.ZonePath) (*privateKeyFile, error) {
	if state == nil {
		return nil, errors.New("join accept requires key.json because no existing state is available")
	}
	if state.ManagedZone != expectedZone {
		return nil, fmt.Errorf("join accept requires key.json because existing state manages %s, not %s", state.ManagedZone, expectedZone)
	}
	if len(state.ZonePrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("join accept requires key.json because existing state has no zone_private_key")
	}
	pub := state.ZonePrivateKey.Public().(ed25519.PublicKey)
	return &privateKeyFile{
		Type:       "photon.ed25519.private.v1",
		PublicKey:  append([]byte(nil), pub...),
		PrivateKey: append([]byte(nil), state.ZonePrivateKey...),
	}, nil
}

func mergeJoinBundleNetwork(dst *zone.NetworkState, src *zone.NetworkState) {
	if dst == nil || src == nil {
		return
	}
	if dst.Zones == nil {
		dst.Zones = make(map[zone.ZonePath]*zone.ZoneState)
	}
	for path, source := range src.Zones {
		if source == nil {
			continue
		}
		target := dst.Zones[path]
		if target == nil {
			dst.Zones[path] = source
			continue
		}
		target.Authority = source.Authority
		target.ParentProof = source.ParentProof
		if target.Delegations == nil {
			target.Delegations = make(map[zone.ZonePath]*zone.Delegation)
		}
		maps.Copy(target.Delegations, source.Delegations)
		if target.Revocations == nil {
			target.Revocations = make(map[zone.ZonePath]*zone.DelegationRevocation)
		}
		maps.Copy(target.Revocations, source.Revocations)
	}
}

func cleanupRevokedPeerState(state *stateFile, revoked zone.ZonePath) {
	if state == nil {
		return
	}
	for peerID := range state.SyncPeers {
		path := zone.ZonePath(peerID)
		if path == revoked || isZoneDescendantOf(path, revoked) {
			delete(state.SyncPeers, peerID)
		}
	}
	for peerID := range state.PeerCleanups {
		path := zone.ZonePath(peerID)
		if path == revoked || isZoneDescendantOf(path, revoked) {
			delete(state.PeerCleanups, peerID)
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
	if err := validatePrivateKeyFile(&key); err != nil {
		return nil, err
	}
	return &key, nil
}

func validatePrivateKeyFile(key *privateKeyFile) error {
	if key == nil {
		return errors.New("private key is nil")
	}
	if key.Type != "photon.ed25519.private.v1" {
		return errors.New("unsupported key file type")
	}
	if len(key.PrivateKey) != ed25519.PrivateKeySize || len(key.PublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid ed25519 key file")
	}
	derived := key.PrivateKey.Public().(ed25519.PublicKey)
	if !equalPublicKey(derived, key.PublicKey) {
		return errors.New("private key does not match public key")
	}
	return nil
}

func validateJoinRequest(request *joinRequest) error {
	if request == nil {
		return errors.New("join request is nil")
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
	return nil
}

func minimalNetworkForJoinBundle(ns *zone.NetworkState, target zone.ZonePath) (*zone.NetworkState, error) {
	if ns == nil {
		return nil, errors.New("network state is nil")
	}
	if !target.Valid() || target == zone.RootZone {
		return nil, fmt.Errorf("invalid join zone: %s", target)
	}
	out := zone.NewNetworkState()
	ancestors := target.Ancestors()
	for _, path := range slices.Backward(ancestors) {

		source := ns.Zones[path]
		if source == nil || source.Authority == nil {
			return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
		}
		zs := zone.NewZoneState(path, cloneAuthorityForJoinBundle(source.Authority))
		if path != zone.RootZone {
			proof, err := directParentProofForBundle(ns, path, source)
			if err != nil {
				return nil, err
			}
			zs.ParentProof = []*zone.Delegation{proof}
		}
		out.Zones[path] = zs
	}
	normalizeState(out)
	return out, nil
}

func directParentProofForBundle(ns *zone.NetworkState, path zone.ZonePath, source *zone.ZoneState) (*zone.Delegation, error) {
	parent := path.Parent()
	if parentState := ns.Zones[parent]; parentState != nil {
		if delegation := parentState.Delegations[path]; delegation != nil {
			return cloneDelegationForJoinBundle(delegation), nil
		}
	}
	for _, proof := range source.ParentProof {
		if proof != nil && proof.ZoneName == path {
			return cloneDelegationForJoinBundle(proof), nil
		}
	}
	return nil, fmt.Errorf("delegation not found: %s", path)
}

func cloneAuthorityForJoinBundle(authority *zone.ZoneAuthority) *zone.ZoneAuthority {
	if authority == nil {
		return nil
	}
	out := &zone.ZoneAuthority{
		Zone:      authority.Zone,
		Epoch:     authority.Epoch,
		Threshold: authority.Threshold,
		Keys:      make([]zone.AuthorizedKey, 0, len(authority.Keys)),
	}
	for _, key := range authority.Keys {
		cloned := zone.AuthorizedKey{
			Key:       append(ed25519.PublicKey(nil), key.Key...),
			NotBefore: key.NotBefore,
			NotAfter:  key.NotAfter,
		}
		if len(key.Capabilities) > 0 {
			cloned.Capabilities = make([]zone.Capability, 0, len(key.Capabilities))
			for _, capability := range key.Capabilities {
				cloned.Capabilities = append(cloned.Capabilities, zone.Capability{
					Permissions: append([]zone.Permission(nil), capability.Permissions...),
					KeyPrefix:   capability.KeyPrefix,
				})
			}
		}
		out.Keys = append(out.Keys, cloned)
	}
	return out
}

func cloneDelegationForJoinBundle(delegation *zone.Delegation) *zone.Delegation {
	if delegation == nil {
		return nil
	}
	out := &zone.Delegation{
		ZoneName:       delegation.ZoneName,
		Scope:          delegation.Scope,
		AuthorityEpoch: delegation.AuthorityEpoch,
		AuthorityHash:  append([]byte(nil), delegation.AuthorityHash...),
		Authority:      *cloneAuthorityForJoinBundle(&delegation.Authority),
		SignedBy:       append(ed25519.PublicKey(nil), delegation.SignedBy...),
		Signature:      append([]byte(nil), delegation.Signature...),
	}
	if delegation.ExpiresAt != nil {
		expiresAt := *delegation.ExpiresAt
		out.ExpiresAt = &expiresAt
	}
	return out
}
