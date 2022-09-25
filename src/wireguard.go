package higgs

import (
	"context"
	"net"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireguardPeer struct {
	wgtypes.PeerConfig
	ctx  context.Context
	Canc context.CancelFunc
}

func (s *WireguardPeer) GetContext() context.Context {
	return s.ctx
}

func (s *WireguardPeer) GetAddr() net.Addr {
	return s.Endpoint
}

type Wireguard struct {
	netlink.LinkAttrs
	CreateNS, RuningNS int
}

func (*Wireguard) LoadFromSys() {
	s, err := netlink.LinkByName()
}
