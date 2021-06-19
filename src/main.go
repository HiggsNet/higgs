package higgs

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
)

func (s *Higgs) Run(configPath string) {
	s.loadConfig(configPath)
	s.init()
	s.P2P.run()
}

func (s *Higgs) GetID(configPath string) {
	s.loadConfig(configPath)
	s.init()
	key, err := crypto.UnmarshalEd25519PrivateKey(ParsePrivateKey(s.P2P.PrivateKey))
	if err != nil {
		s.log.Fatalf("parse private key failed. %s", err)
	}
	host, _ := libp2p.New(context.Background(), libp2p.Identity(key))
	publicKey := base64.StdEncoding.EncodeToString([]byte(ParsePrivateKey(s.P2P.PrivateKey).Public().(ed25519.PublicKey)))
	fmt.Printf("Public Key:\t%s\nP2P ID:\t\t%s\n", publicKey, host.ID().String())
}

func (s *Higgs) Sign(configPath string, domain string, key string) {
	// s.loadConfig(configPath)

	// s.init()
	// if s.am.manageKey == nil {
	// 	s.log.Fatalf("manage key missing.")
	// }
	// authMessage := AuthMessage{
	// 	Domain:    domain,
	// 	Key:       key,
	// 	Timestamp: time.Now().UnixNano(),
	// }
	// m := message{&authMessage}
	// m.sign(s.am.manageKey)
	// fmt.Printf("{\nDomain= \"%s\"\nKey= \"%s\"\nTimestamp= %d\nSign= \"%s\"\n}\n",
	// 	domain, key, authMessage.Timestamp, authMessage.Sign)
}
