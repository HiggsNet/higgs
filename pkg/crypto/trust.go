package crypto

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// VerifyPinnedRoot requires the configured Ed25519 key to be present in the
// root authority. Linux and leaf clients share this trust-anchor check.
func VerifyPinnedRoot(ns *zone.NetworkState, trusted ed25519.PublicKey) error {
	if len(trusted) != ed25519.PublicKeySize {
		return errors.New("trusted root public key must be an Ed25519 public key")
	}
	if ns == nil {
		return errors.New("trusted root public key configured but network state is nil")
	}
	root := ns.Zones[zone.RootZone]
	if root == nil || root.Authority == nil {
		return errors.New("trusted root public key configured but root authority is missing")
	}
	for _, key := range root.Authority.Keys {
		if len(key.Key) == len(trusted) && subtle.ConstantTimeCompare(key.Key, trusted) == 1 {
			return nil
		}
	}
	return errors.New("root authority does not match trusted_root_public_key")
}
