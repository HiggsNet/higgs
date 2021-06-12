package higgs

import (
	"context"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/syndtr/goleveldb/leveldb"
	"go.uber.org/zap"
)

type server struct {
	config
	log  *zap.SugaredLogger
	host host.Host
	ctx  context.Context
	ps   *pubsub.PubSub
	db   *leveldb.DB
	nm   *nodeManager
}

func (s *server) init() *server {
	s.log = s.config.log.With("server")
	var err error
	if s.db, err = leveldb.OpenFile(s.config.Database, nil); err != nil {
		s.log.Fatalf("load database failed")
	}
	s.nm = (&nodeManager{}).init(s.db, s.log)
	return s
}

func (s *server) getBootNodes() []string {
	addrs := make([]string, 0)
	if s.BootNode != "" {
		addrs = append(addrs, s.BootNode)
	}
	for _, v := range s.nm.nodes {
		addrs = append(addrs, v.Address)
	}
	return addrs
}

func (s *server) boot() bool {
	done := make(chan bool)
	ctx := context.Background()
	for _, v := range s.getBootNodes() {
		go func(addrs string, done chan bool) {
			s.log.Debugf("try to connect to %s", addrs)
			ma, err := ma.NewMultiaddr(addrs)
			if err != nil {
				s.log.Warnf("connect to %s failed, parse address failed. %s", err)
				return
			}
			pi, err := peer.AddrInfoFromP2pAddr(ma)
			if err != nil {
				s.log.Warnf("connect to %s failed, parse address failed. %s", err)
				return
			}
			s.host.Connect(ctx, *pi)
			s.log.Debugf("%s connected", addrs)
			done <- true
		}(v, done)
	}
	select {
	case <-done:
		return true
	}
}

func (s *server) run() {
	ctx := context.Background()
	var err error
	key, err := crypto.UnmarshalEd25519PrivateKey([]byte(ParsePrivateKey(s.PrivateKey)))
	if err != nil {
		s.log.Fatalf("parse private key failed. %s", err)
	}
	if s.host, err = libp2p.New(ctx, libp2p.Identity(key), libp2p.ListenAddrStrings(s.config.Address)); err != nil {
		s.log.Fatalf("listen libp2p failed.%s", err)
	}
	s.log.Infof("start p2p listen on %s, public key: %s.", s.host.Addrs(), s.host.ID().String())
	if s.ps, err = pubsub.NewGossipSub(ctx, s.host); err != nil {
		s.log.Fatal("subpub create failed", err)
	}
	s.boot()
	<-make(chan bool)
}
