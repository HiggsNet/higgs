package higgs

import (
	"context"
	"net"

	"go.uber.org/zap"
)

type TunnelPeer interface {
	GetAddr() net.Addr
	GetContext() context.Context
}

type TunnelConfig struct {
	Name     string             `hcl:"name,label"`
	ParentNS int                `hcl:"parent_ns,optional"`
	DestNS   int                `hcl:"dest_ns,optional"`
	Mtu      int                `hcl:"mtu,optional"`
	Addr     []string           `hcl:"addr,optional"`
	LLAddr   []string           `hcl:"lladdr,optional"`
	Inet     string             `hcl:"inet,attr"` //"should be inet or inet6"
	log      *zap.SugaredLogger `hcl:"-"`
}

func (s *TunnelConfig) init(logger *zap.SugaredLogger) {
	s.log = logger.With("name", s.Name)
}

// type Tunnel interface {
// 	Init(Name string) error

// 	LoadFromSys() error

// 	GetAddrs() []net.Addr
// 	AddAddrs([]net.Addr) error
// 	DelAddrs([]net.Addr) error

// 	GetMtu() int
// 	SetMtu(int) error

// 	Create() error
// 	Delete() error

// 	Up() error
// 	Down() error

// 	GetPeers() []*TunnelPeer
// 	AddPeer([]*TunnelPeer) error
// 	DelPeer([]*TunnelPeer) error
// 	UpdatePeer(*TunnelPeer) error
// }
