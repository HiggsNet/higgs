package higgs

import "crypto/ed25519"

type message struct {
	Domain  string
	Type    string
	Message []byte
	Sign    []byte
}

func (s *message) valid(key ed25519.PublicKey) bool {
	return ed25519.Verify(key, s.Message, s.Sign)
}

type rootMessage struct {
	CA string
}
