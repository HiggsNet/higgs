package higgs

import (
	"io/ioutil"
	"log"

	"github.com/hashicorp/hcl/v2/hclsimple"
	"github.com/syndtr/goleveldb/leveldb"
	"go.uber.org/zap"
)

type Higgs struct {
	log      *zap.SugaredLogger
	P2P      p2p    `hcl:"p2p,block"`
	Database string `hcl:"Database,optional"`
	Socket   string `hcl:"Socket,optional"`
	Debug    bool   `hcl:"Debug,optional"`
	db       *leveldb.DB
	nm       *nodeManager
	am       *authManager
}

func (s *Higgs) loadConfig(path string) *Higgs {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Read config file failed %s", err)
	}
	err = hclsimple.Decode("higgs.hcl", data, nil, s)
	if err != nil {
		log.Fatalf("Parse config file failed, %s", err)
	}
	if s.Database == "" {
		s.Database = "./.higgs.db"
	}
	if s.Socket == "" {
		s.Socket = "/tmp/higgs.sock"
	}
	logConfig := zap.NewDevelopmentConfig()
	logConfig.DisableStacktrace = true
	if s.Debug {
		logConfig.Level.SetLevel(zap.DebugLevel)
	} else {
		logConfig.Level.SetLevel(zap.InfoLevel)
	}
	logger, _ := logConfig.Build()
	zap.ReplaceGlobals(logger)
	s.log = logger.Sugar()
	return s
}

func (s *Higgs) init() {
	var err error

	//Init Database
	if s.db, err = leveldb.OpenFile(s.Database, nil); err != nil {
		s.log.Fatalf("load database failed")
	}
	//Init NodeManager
	s.nm = (&nodeManager{}).init(s.db, s.log)
	//Init AuthManager
	s.am = (&authManager{}).init(s.db, &s.P2P)
	//Init P2P
	s.P2P.init(s.log, s.nm, s.am)

}
