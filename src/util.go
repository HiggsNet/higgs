package higgs

import (
	"crypto/ed25519"
	"encoding/base64"
)

func ParsePublicKey(s string) ed25519.PublicKey {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return ed25519.PublicKey(b)
}

func ParsePrivateKey(s string) ed25519.PrivateKey {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return ed25519.PrivateKey(b)
}
