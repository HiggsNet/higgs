package higgs

import (
	"io/ioutil"
	"log"

	"github.com/hashicorp/hcl/v2/hclsimple"
	"go.uber.org/zap"
)

type config struct {
	log        *zap.SugaredLogger
	TrustCA    string `hcl:"trust_ca,attr"`
	BootNode   string `hcl:"boot_node,optional"`
	Database   string `hcl:"database,optional"`
	PrivateKey string `hcl:"pirvate_key,attr"`
	Address    string `hcl:"address,attr"`
	Socket     string `hcl:"socket,optional"`
	Debug      bool   `hcl:"debug,option"`
}

func loadConfig(path string) *config {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Read config file failed %s", err)
	}
	c := &config{}
	err = hclsimple.Decode("higgs.hcl", data, nil, c)
	if err != nil {
		log.Fatalf("Parse config file failed, %s", err)
	}
	if c.Database == "" {
		c.Database = "./.higgs.db.json"
	}
	if c.Socket == "" {
		c.Socket = "/tmp/higgs.sock"
	}
	logConfig := zap.NewDevelopmentConfig()
	logConfig.DisableStacktrace = true
	if c.Debug {
		logConfig.Level.SetLevel(zap.DebugLevel)
	} else {
		logConfig.Level.SetLevel(zap.InfoLevel)
	}
	logger, _ := logConfig.Build()
	zap.ReplaceGlobals(logger)
	c.log = logger.Sugar()
	return c
}
