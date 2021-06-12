package higgs

import (
	"encoding/json"

	"github.com/syndtr/goleveldb/leveldb"
	"go.uber.org/zap"
)

type node struct {
	PublicKey string
	Domain    string
	Address   string
	db        *leveldb.DB
	log       *zap.SugaredLogger
}

func (s *node) init(domain string, db *leveldb.DB, log *zap.SugaredLogger) *node {
	s.db = db
	s.Domain = domain
	s.log = log.With(s.Domain)
	s.load()
	return s
}

func (s *node) save() error {
	if data, err := json.Marshal(s); err != nil {
		s.log.Warnf("save node failed, marshal failed, %s", err)
		return err
	} else {
		err = s.db.Put([]byte(s.Domain), data, nil)
		if err != nil {
			s.log.Warnf("save node failed, db failed, %s", err)
		}
		return err
	}
}

func (s *node) load() error {
	if data, err := s.db.Get([]byte(s.Domain), nil); err != nil {
		s.log.Warnf("load node failed, db failed, %s", err)
		return err
	} else {
		err = json.Unmarshal(data, s)
		if err != nil {
			s.log.Warnf("load node failed, unmarshal failed, %s", err)
		}
		return err
	}
}

func (s *node) validMessage(m *message) bool {
	if key := ParsePublicKey(s.PublicKey); key != nil {
		return m.valid(key)
	}
	return false
}

type nodeManager struct {
	nodes map[string]node
	db    *leveldb.DB
	log   *zap.SugaredLogger
}

func (s *nodeManager) init(db *leveldb.DB, log *zap.SugaredLogger) *nodeManager {
	s.db = db
	s.log = log.With("nodeManager")
	s.nodes = make(map[string]node)
	nodeList := s.getNodeListFromDB()
	for _, v := range nodeList {
		n := (&node{}).init(v, s.db, s.log)
		s.nodes[v] = *n
	}
	return s
}

func (s *nodeManager) getNodeListFromDB() []string {
	result := make([]string, 0)
	data, err := s.db.Get([]byte("nodeList"), nil)
	if err != nil {
		s.log.Warnf("load nodes failed, db failed, %s", err)
		return result
	}
	err = json.Unmarshal(data, &result)
	if err != nil {
		s.log.Warnf("load nodes failed, unmarshal failed, %s", err)
	}
	return result
}

func (s *nodeManager) newNode(domain string) *node {
	if _, ok := s.nodes[domain]; ok {
		s.log.Warnf("node duplicate, %s", domain)
		return nil
	}
	nodeList := s.getNodeListFromDB()
	nodeList = append(nodeList, domain)
	data, _ := json.Marshal(nodeList)
	if err := s.db.Put([]byte("nodeList"), data, nil); err != nil {
		s.log.Warnf("create node failed, %s", domain)
		return nil
	}
	n := (&node{}).init(domain, s.db, s.log)
	return n
}
