package higgs

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	ma "github.com/multiformats/go-multiaddr"
	"go.uber.org/zap"
)

type p2p struct {
	TrustCA       string        `hcl:"TrustCA,attr"`
	PrivateKey    string        `hcl:"PrivateKey,attr"`
	Address       string        `hcl:"Address,attr"`
	ManageKey     string        `hcl:"ManageKey,optional"`
	BootNode      string        `hcl:"BootNode,optional"`
	Auth          []AuthMessage `hcl:"Auth,block"`
	log           *zap.SugaredLogger
	host          host.Host
	ctx           context.Context
	ps            *pubsub.PubSub
	nm            *nodeManager
	am            *authManager
	nodeTopic     *pubsub.Topic
	nodeSubscribe *pubsub.Subscription
	authTopic     *pubsub.Topic
	authSubscribe *pubsub.Subscription
	hostConnect   chan bool
}

func (s *p2p) init(log *zap.SugaredLogger, nm *nodeManager, am *authManager) *p2p {
	s.log = log
	s.nm = nm
	s.am = am
	s.hostConnect = make(chan bool)
	return s
}

func (s *p2p) getBootNodes() []string {
	addrs := make([]string, 0)
	if s.BootNode != "" {
		addrs = append(addrs, s.BootNode)
	}
	for _, v := range s.nm.nodes {
		addrs = append(addrs, v.Address)
	}
	return addrs
}

func (s *p2p) boot() {
	ctx := context.Background()
	for _, v := range s.getBootNodes() {
		go func(addrs string, done chan bool) {
			s.log.Debugf("try to connect to %s", addrs)
			ma, err := ma.NewMultiaddr(addrs)
			if err != nil {
				s.log.Warnf("connect to %s failed, parse address failed. %s", addrs, err)
				return
			}
			pi, err := peer.AddrInfoFromP2pAddr(ma)
			if err != nil {
				s.log.Warnf("connect to %s failed, parse address failed. %s", addrs, err)
				return
			}
			if err := s.host.Connect(ctx, *pi); err != nil {
				s.log.Debugf("connect to %s failed. %s", addrs, err)
			} else {
				s.log.Debugf("%s connected", addrs)
				s.hostConnect <- true
			}
		}(v, s.hostConnect)
	}
}

func (s *p2p) run() {
	ctx := context.Background()
	var err error
	key, err := crypto.UnmarshalEd25519PrivateKey(ParsePrivateKey(s.PrivateKey))
	if err != nil {
		s.log.Fatalf("parse private key failed. %s", err)
	}
	if s.host, err = libp2p.New(ctx, libp2p.Identity(key), libp2p.ListenAddrStrings(strings.Split(s.Address, ",")...)); err != nil {
		s.log.Fatalf("listen libp2p failed.%s", err)
	}
	s.log.Infof("start p2p listen on %s, id: %s", s.host.Addrs(), s.host.ID().String())
	if s.ps, err = pubsub.NewGossipSub(ctx, s.host); err != nil {
		s.log.Fatal("subpub create failed", err)
	}
	s.boot()
	if s.authTopic, err = s.ps.Join("auth"); err != nil {
		s.log.Fatal("get topic failed. %s", err)
	}
	if s.authSubscribe, err = s.authTopic.Subscribe(); err != nil {
		s.log.Fatal("get subscript failed. %s", err)
	}
	go s.authLoop()
	if s.nodeTopic, err = s.ps.Join("node"); err != nil {
		s.log.Fatal("get topic failed. %s", err)
	}
	if s.nodeSubscribe, err = s.nodeTopic.Subscribe(); err != nil {
		s.log.Fatal("get subscript failed. %s", err)
	}
	go s.nodeLoop()
	<-make(chan bool)
}

func (s *p2p) nodeLoop() {
	for {
		m, err := s.nodeSubscribe.Next(context.Background())
		if err != nil {
			s.log.Warnf("node loop failed, %s", err)
			time.Sleep(1 * time.Second)
			continue
		}
		data := m.GetData()
		nodeMessage := &nodeMessage{}
		json.Unmarshal(data, nodeMessage)
		s.handleNodeMessage(nodeMessage)
	}
}

func (s *p2p) handleNodeMessage(m *nodeMessage) {
	// mm := message{m}
	// if !s.am.verify(mm) {
	// 	s.log.Warnf("unauth node message received. Domain: %s.", m.getDomain())
	// 	return
	// }
	// return
}

func (s *p2p) authLoop() {
	for {
		m, err := s.authSubscribe.Next(context.Background())
		if err != nil {
			s.log.Warnf("auth loop failed, %s", err)
			time.Sleep(1 * time.Second)
			continue
		}
		data := m.GetData()
		authMessage := &AuthMessage{}
		json.Unmarshal(data, authMessage)
		if !s.am.add(*authMessage, false) {
			s.log.Warnf("unauth auth message received. Domain: %s", authMessage.getDomain())
		}
	}
}
