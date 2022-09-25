package higgs

import (
	"context"
	"net"

	"github.com/vishvananda/netlink"
)

type TunnelPeer interface {
	GetAddr() net.Addr
	GetContext() context.Context
}

type Tunnel interface {
	Init(Name string) error

	LoadFromSys() error

	GetNs() int
	SetNs(int) error
	MoveNs(int) error

	GetMac() netlink.Addr
	SetMac(netlink.Addr) error

	GetAddrs() []net.Addr
	AddAddrs([]net.Addr) error
	DelAddrs([]net.Addr) error

	GetMut() int
	SetMtu(int) error

	Create() error
	Delete() error

	Up() error
	Down() error

	GetPeers() []*TunnelPeer
	AddPeer([]*TunnelPeer) error
	DelPeer([]*TunnelPeer) error
	UpdatePeer(*TunnelPeer) error
}
