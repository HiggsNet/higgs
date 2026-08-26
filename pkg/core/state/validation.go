package state

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

var ErrInvalidStateRoot = errors.New("state root is invalid")

// ValidateStateRoot checks startup/schema invariants without mutating or
// retaining the supplied root. Gossip checkpoints are deliberately excluded:
// malformed loss-tolerant hints may be discarded without weakening trust.
func ValidateStateRoot(state *VerifiedState) error {
	if state == nil || state.Network == nil {
		return fmt.Errorf("%w: network is missing", ErrInvalidStateRoot)
	}
	if !state.ManagedZone.Valid() || state.Network.Zones[state.ManagedZone] == nil {
		return fmt.Errorf("%w: managed zone %q is missing", ErrInvalidStateRoot, state.ManagedZone)
	}
	if err := validateOptionalPrivateKey("root", state.RootPrivateKey); err != nil {
		return err
	}
	if err := validateOptionalPrivateKey("identity", state.IdentityPrivateKey); err != nil {
		return err
	}
	if len(state.TrustedRootPublicKey) != 0 {
		if err := photoncrypto.VerifyPinnedRoot(state.Network, state.TrustedRootPublicKey); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidStateRoot, err)
		}
	}
	return nil
}

func validateOptionalPrivateKey(name string, key ed25519.PrivateKey) error {
	if len(key) != 0 && len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: %s private key length is %d", ErrInvalidStateRoot, name, len(key))
	}
	return nil
}
