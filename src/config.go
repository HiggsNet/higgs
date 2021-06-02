package higgs

import (
	"io/ioutil"
	"log"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

//Higgs is the model of higgs.conf
type Higgs struct {
	Name       string `hcl:"name,attr"`
	Etcd       string `hcl:"etcd,attr"`
	TrustCA    string `hcl:"trust_ca,attr"`
	PrivateKey string `hcl:"pirvate_key,attr"`
	CachePath  string `hcl:"cache_path,optional"`
}

//LoadConf func load and parse config.
func (h *Higgs) LoadConf(path string) *Higgs {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Read config file failed %s", err)
	}
	err = hclsimple.Decode("higgs.hcl", data, nil, h)
	if err != nil {
		log.Fatalf("Parse config file failed, %s", err)
	}
	return h
}
