package bird

import (
	"encoding/binary"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

// StableRouterID returns a deterministic 32-bit router id for an overlay.
// It hashes the local zone, the trusted root hash, and the overlay id,
// then maps the first four bytes of the digest to a non-zero uint32.
func StableRouterID(localZone zone.ZonePath, rootTrust []byte, overlayID string) uint32 {
	digest := higgscrypto.Hash(
		[]byte(localZone),
		rootTrust,
		[]byte(overlayID),
	)
	id := binary.BigEndian.Uint32(digest[:4])
	if id == 0 {
		id = 0x80000001 // 128.0.0.1; avoid the all-zero router id
	}
	return id
}
