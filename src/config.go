package higgs

import (
	"crypto/ed25519"
	"log"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

// Config is a global config.
type Config struct {
	Name             string             `hcl:"name,attr"`         //Shoule be example.catofes.
	Key              string             `hcl:"key,attr,optional"` //TODO: PrivKey to update configs.
	privKey          ed25519.PrivateKey `hcl:"-"`
	Root             string             `hcl:"root,attr"`    //Global network configs. Should be URL or file.
	Ifgroup          int                `hcl:"ifgroup,attr"` //Ifgroup for isolation.
	WireguardConfigs []WireguardConfig  `hcl:"wireguard,block"`
}

// Load loads config from path.
func (s *Config) Load(path string) {
	err := hclsimple.DecodeFile(path, nil, s)
	if err != nil {
		log.Fatal(err)
	}
	s.privKey = ed25519.PrivateKey([]byte(s.Key))
}
