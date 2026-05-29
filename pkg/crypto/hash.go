package crypto

import "golang.org/x/crypto/blake2b"

func Hash(parts ...[]byte) []byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}

func KeyID(pub []byte) []byte {
	return Hash(pub)
}
