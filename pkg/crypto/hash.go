package crypto

import "crypto/sha256"

// Hash currently uses SHA-256 as the repository-local digest primitive.
// The design calls for blake2b; keeping this wrapper limits the replacement.
func Hash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}

func KeyID(pub []byte) []byte {
	return Hash(pub)
}
