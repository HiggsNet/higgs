package higgs

import (
	"context"
	"encoding/json"
	"reflect"
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
	privateKey string
	listen     string
	id         string

	log         *zap.SugaredLogger
	host        host.Host
	ps          *pubsub.PubSub
	topic       *pubsub.Topic
	subscribe   *pubsub.Subscription
	hostConnect chan bool
	recvMessage chan *pubsub.Message
}

func (s *p2p) init(log *zap.SugaredLogger) *p2p {
	s.log = log
	s.hostConnect = make(chan bool)
	return s
}

func (s *p2p) connect(addrs string) {
	if addrs == "" {
		return
	}
	s.log.Debugf("try to connect to %s", addrs)
	addrList := strings.Split(addrs, ",")
	for _, v := range addrList {
		if v == "" {
			continue
		}
		ma, err := ma.NewMultiaddr(v)
		if err != nil {
			s.log.Warnf("connect to %s failed, parse address failed. %s", v, err)
			return
		}
		pi, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			s.log.Warnf("connect to %s failed, parse address failed. %s", v, err)
			return
		}
		if err := s.host.Connect(context.Background(), *pi); err != nil {
			s.log.Debugf("connect to %s failed. %s", v, err)
		} else {
			s.log.Debugf("%s connected", v)
			s.hostConnect <- true
		}
	}
}

func (s *p2p) run() {
	ctx := context.Background()
	var err error
	key, err := crypto.UnmarshalEd25519PrivateKey(ParsePrivateKey(s.privateKey))
	if err != nil {
		s.log.Fatalf("parse private key failed. %s", err)
	}
	if s.host, err = libp2p.New(ctx, libp2p.Identity(key), libp2p.ListenAddrStrings(strings.Split(s.listen, ",")...)); err != nil {
		s.log.Fatalf("listen libp2p failed.%s", err)
	}
	s.id = s.host.ID().String()
	s.log.Infof("start p2p listen on %s, id: %s", s.host.Addrs(), s.host.ID().String())
	if s.ps, err = pubsub.NewGossipSub(ctx, s.host); err != nil {
		s.log.Fatal("subpub create failed", err)
	}
	if s.topic, err = s.ps.Join("node"); err != nil {
		s.log.Fatal("get topic failed. %s", err)
	}
	if s.subscribe, err = s.topic.Subscribe(); err != nil {
		s.log.Fatal("get subscript failed. %s", err)
	}
	go s.loop()
}

func (s *p2p) loop() {
	for {
		m, err := s.subscribe.Next(context.Background())
		if err != nil {
			s.log.Warnf("node loop failed, %s", err)
			time.Sleep(1 * time.Second)
			continue
		}
		s.recvMessage <- m
	}
}

func (s *p2p) broadcast(m rawMessage) bool {
	if data, err := json.Marshal(message{
		Type:    reflect.TypeOf(m).String(),
		Message: m.Dump(),
	}); err != nil {
		s.log.Warnf("broadcast message failed, %s", err)
		return false
	} else {
		if err := s.topic.Publish(context.Background(), data); err != nil {
			s.log.Warnf("broadcast message failed, %s", err)
			return false
		}
	}
	return true
}
