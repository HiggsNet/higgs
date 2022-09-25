package higgs

import (
	"log"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

type Config struct {
	Name string `hcl:"Name,attr"`
	Key  string `hcl:"key,attr"`
	Root string `hcl:"Root,attr"`
}

func (s *Config) Load(path string) {
	err := hclsimple.DecodeFile(path, nil, s)
	if err != nil {
		log.Fatal(err)
	}
}
