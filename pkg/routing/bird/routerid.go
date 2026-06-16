package bird

import (
	"encoding/binary"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

// StableRouterID returns a deterministic 32-bit router id for a BIRD instance
// running in a specific network namespace. It hashes the local zone, the
// trusted root hash, and the netns name, then maps the first four bytes of
// the digest to a non-zero uint32.
//
// In the per-netns model, one netns = one BIRD instance = one Router-ID.
// The netnsName should be the stable identifier returned by NetNSSpec.Target()
// (e.g. "h2" for a named netns, "host" for the host netns). For path netns,
// the caller must supply an explicit router_id_label from configuration.
func StableRouterID(localZone zone.ZonePath, rootTrust []byte, netnsName string) uint32 {
	digest := higgscrypto.Hash(
		[]byte(localZone),
		rootTrust,
		[]byte(netnsName),
	)
	id := binary.BigEndian.Uint32(digest[:4])
	if id == 0 {
		id = 0x80000001 // 128.0.0.1; avoid the all-zero router id
	}
	return id
}
