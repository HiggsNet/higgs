package higgs

import (
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"strings"
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"go.uber.org/zap"
)

type rawMessage interface {
	//return Domain of message
	getDomain() string
	//return message data without sign
	getMessage() string
	//return sign data
	getSign() string
	//set the sign
	setSign(string)
	//load message from string
	load(string) error
	//return message data with sign
	dump() string
}

type message struct {
	rawMessage
	Message string
	Type    string
	managed bool
}

func (s *message) sign(key ed25519.PrivateKey) string {
	s.setSign(Ed25519Sign(key, s.getMessage()))
	return s.getSign()
}

func (s *message) verify(key ed25519.PublicKey) bool {
	return Ed25519Verify(key, s.getMessage(), s.getSign())
}

func (s *message) parse(t reflect.Type) rawMessage {
	value := reflect.New(t)
	value.MethodByName("new").Call([]reflect.Value{reflect.ValueOf(s.Message)})
	if r := recover(); r != nil {
		return nil
	}
	s.rawMessage = value.Interface().(rawMessage)
	return s.rawMessage
}

type messageManager struct {
	log    *zap.SugaredLogger
	db     *leveldb.DB
	values map[string]message
	types  map[string]reflect.Type
	ca     ed25519.PublicKey
	mutex  sync.Mutex
}

func (s *messageManager) Init(db *leveldb.DB, log *zap.SugaredLogger) {
	s.db = db
	s.log = log
	s.values = make(map[string]message)
	s.types = make(map[string]reflect.Type)
}

func (s *messageManager) Register(t rawMessage) {
	tt := reflect.TypeOf(t)
	s.types[tt.String()] = tt
}

func (s *messageManager) loadAllFromDB() error {
	iter := s.db.NewIterator(nil, nil)
	for iter.Next() {
		k := iter.Key()
		s.loadFromDB(string(k))
	}
	return nil
}

func (s *messageManager) loadFromDB(domain string) bool {
	if data, err := s.db.Get([]byte(domain), nil); err == nil {
		m := message{}
		if err := json.Unmarshal(data, m); err != nil {
			s.log.Warnf("load data from db failed. %s", err)
			return false
		}
		if v, ok := s.types[m.Type]; !ok {
			s.log.Warnf("unknown type %s from db.", m.Type)
			return false
		} else {
			if m.parse(v) == nil {
				s.log.Warnf("reflect value failed. %s:%s", domain, v)
				return false
			} else {
				return s.add(m.rawMessage, false, false, false)
			}
		}
	}
	return false
}

func (s *messageManager) verify(m rawMessage) bool {
	domain := m.getDomain()
	domains := strings.Split(domain, ".")
	for i := 1; i < len(domains); i++ {
		domain := strings.Join(domains[i:], ".") + "."
		var a rawMessage
		if t, ok := s.values[domain]; ok {
			a = t
		} else {
			if s.loadFromDB(domain) {
				a = s.values[domain]
			}
		}
		if a != nil {
			if v, ok := a.(*AuthMessage); ok {
				m := message{rawMessage: m}
				if m.verify(v.getKey()) {
					return true
				}
			}
		}
	}
	return false
}

func (s *messageManager) add(m rawMessage, force bool, save bool, managed bool) bool {
	s.log.Debugf("add message at %s.", m.getDomain())
	if !force && !s.verify(m) {
		s.log.Warnf("message at %s auth failed.", m.getDomain())
		return false
	}
	mm := message{rawMessage: m}
	if managed {
		mm.managed = true
	}
	s.values[m.getDomain()] = mm
	if save {
		if data, err := json.Marshal(message{
			Type:    reflect.TypeOf(m).String(),
			Message: m.dump(),
		}); err != nil {
			s.log.Warnf("save message failed, %s", err)
			return false
		} else {
			if err := s.db.Put([]byte(m.getDomain()), data, nil); err != nil {
				s.log.Warnf("save message failed, %s", err)
				return false
			}
		}
	}
	return true
}
