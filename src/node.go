package node

import (
	"crypto/ed25519"

	"github.com/BurntSushi/toml"
)

// Self is a Node. Node is everything.
type Node struct {
	Name       string
	Key        string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func (s *Node) loadConfig(path string) {
	if _, err := toml.Decode(path, s); err != nil {
		panic(err)
	}
}

func (s *Node) Init(path string) {
	s.loadConfig(path)

	s.privateKey = ed25519.PrivateKey([]byte(s.Key))
	s.publicKey = s.privateKey.Public().(ed25519.PublicKey)
}
