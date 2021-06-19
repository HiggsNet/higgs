package higgs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
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

func GenerateKey() string {
	pubkey, prikey, _ := ed25519.GenerateKey(rand.Reader)
	pub := base64.StdEncoding.EncodeToString(pubkey)
	pri := base64.StdEncoding.EncodeToString(prikey)
	key, _ := crypto.UnmarshalEd25519PrivateKey(prikey)
	host, _ := libp2p.New(context.Background(), libp2p.Identity(key))
	return fmt.Sprintf("Public Key:\t%s \nPrivate Key:\t%s \nP2P ID:\t\t%s\n", pub, pri, host.ID().String())
}

func Ed25519Sign(key ed25519.PrivateKey, message string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(message)))
}

func Ed25519Verify(key ed25519.PublicKey, message string, sign string) bool {
	if d, err := base64.RawStdEncoding.DecodeString(sign); err != nil {
		return ed25519.Verify(key, []byte(message), d)
	}
	return false
}
