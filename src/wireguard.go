package higgs

import (
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireguardPeer struct {
	wgtypes.PeerConfig
}

type WireguardConfig struct {
	wgtypes.Config
	TunnelConfig
	Privkey string `hcl:"Privkey,attr"`
	Port    int    `hcl:"Port,attr"`
	Host    string `hcl:"Host,attr"`
}

func (s *WireguardConfig) init(logger *zap.SugaredLogger) {
	s.TunnelConfig.init(logger)
	s.log = s.TunnelConfig.log.With("type", "wireguard")
	s.log.Debug("Init WireguardConfig")
	s.Config = wgtypes.Config{}
	if privKey, err := wgtypes.ParseKey(s.Privkey); err != nil {
		s.log.Fatal(err)
	} else {
		s.Config.PrivateKey = &privKey
	}
	s.Config.ListenPort = &s.Port
}

func (s *WireguardConfig) LoadFromSys() {

}

func (s *WireguardConfig) apply() {
	s.log.Debug("Apply WireguardConfig")
}
