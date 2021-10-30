package higgs

import (
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/syndtr/goleveldb/leveldb"
	"go.uber.org/zap"
)

type rawMessage interface {
	//return Domain of message
	GetDomain() string
	//return message data without sign
	GetMessage() string
	//return sign data
	GetSign() string
	//set the sign
	SetSign(string)
	//get message timestamp
	GetTimestamp() int64
	//load message from string
	Load(string) error
	//return message data with sign
	Dump() string
}

type message struct {
	rawMessage `json:"ignore"`
	Message    string
	Type       string
	Managed    bool
}

func (s *message) sign(key ed25519.PrivateKey) string {
	//log.Printf("%s:%s", s.getMessage(), Ed25519Sign(key, s.getMessage()))
	s.SetSign(Ed25519Sign(key, s.GetMessage()))
	return s.GetSign()
}

func (s *message) verify(key ed25519.PublicKey) bool {
	//log.Printf("%s:%s", s.getMessage(), s.getSign())
	return Ed25519Verify(key, s.GetMessage(), s.GetSign())
}

func (s *message) parse(t reflect.Type) rawMessage {
	value := reflect.New(t.Elem())
	value.MethodByName("Load").Call([]reflect.Value{reflect.ValueOf(s.Message)})
	if r := recover(); r != nil {
		return nil
	}
	s.rawMessage = value.Interface().(rawMessage)
	return s.rawMessage
	//return nil
}

type messageManager struct {
	Domain     string        `hcl:"Domain,attr"`
	TrustCA    string        `hcl:"TrustCA,attr"`
	PrivateKey string        `hcl:"PrivateKey,attr"`
	Listen     string        `hcl:"Listen,attr"`
	Addresses  string        `hcl:"Addresses,optional"`
	BootNode   string        `hcl:"BootNode,optional"`
	Auth       []AuthMessage `hcl:"Auth,block"`

	timestamp   int64
	privateKey  ed25519.PrivateKey
	log         *zap.SugaredLogger
	db          *leveldb.DB
	p2p         *p2p
	values      map[string]message
	types       map[string]reflect.Type
	mutex       sync.Mutex
	handler     func(new rawMessage, old rawMessage)
	sendMessage chan string
	recvMessage chan *pubsub.Message
}

func (s *messageManager) Init(db *leveldb.DB, log *zap.SugaredLogger) {
	s.db = db
	s.log = log
	s.timestamp = time.Now().UnixNano()
	s.values = make(map[string]message)
	s.types = make(map[string]reflect.Type)
	s.privateKey = ParsePrivateKey(s.PrivateKey)
	s.sendMessage = make(chan string)
	s.recvMessage = make(chan *pubsub.Message, 30)
	if s.privateKey == nil {
		s.log.Fatalf("load private key failed.")
	}
	s.Register(&AuthMessage{})
	s.Register(&NodeMessage{})
	s.Register(&PeerMessage{})
	s.initAuth()
}

func (s *messageManager) Register(t rawMessage) {
	tt := reflect.TypeOf(t)
	s.types[tt.String()] = tt
}

func (s *messageManager) initAuth() {
	m := AuthMessage{
		Domain:    ".",
		Key:       s.TrustCA,
		Timestamp: time.Now().UnixNano(),
	}
	s.add(&m, true, false, false)
	for _, v := range s.Auth {
		s.add(&v, false, true, true)
	}
}

func (s *messageManager) loadAllFromDB() error {
	iter := s.db.NewIterator(nil, nil)
	for iter.Next() {
		k := iter.Key()
		s.loadFromDB(string(k))
	}
	return nil
}

func (s *messageManager) loadFromByte(data []byte) rawMessage {
	m := &message{}
	if err := json.Unmarshal(data, m); err != nil {
		s.log.Warnf("load data from db failed. %s", err)
		return nil
	}
	if v, ok := s.types[m.Type]; !ok {
		s.log.Warnf("unknown type %s from db.", m.Type)
		return nil
	} else {
		if m.parse(v) == nil {
			s.log.Warnf("reflect value failed. %s", v)
			return nil
		} else {
			return m.rawMessage
		}
	}
}

func (s *messageManager) loadFromDB(domain string) bool {
	if data, err := s.db.Get([]byte(domain), nil); err == nil {
		if rawMessage := s.loadFromByte(data); rawMessage != nil {
			//s.log.Debugf("add message at <%s> from db", rawMessage.GetDomain())
			return s.add(rawMessage, false, false, false)
		} else {
			s.log.Warnf("load %s from db failed.", domain)
			return false
		}
	}
	return false
}

func (s *messageManager) verify(m rawMessage) bool {
	domain := strings.Trim(strings.Trim(m.GetDomain(), "."), "@")
	t := strings.Split(domain, ".")
	domains := make([]string, 0)
	for i := 0; i < len(t); i++ {
		domains = append(domains, strings.Join(t[i:], ".")+".")
	}
	domains = append(domains, ".")
	if m.GetDomain()[len(m.GetDomain())-1] == '.' {
		domains = domains[1:]
	}
	for _, domain := range domains {
		//log.Println(domain)
		var a rawMessage
		if t, ok := s.values[domain]; ok {
			a = t.rawMessage
		} else {
			if s.loadFromDB(domain) {
				a = s.values[domain].rawMessage
			}
		}
		if a != nil {
			if v, ok := a.(*AuthMessage); ok {
				m := message{rawMessage: m}
				if m.verify(v.GetKey()) {
					return true
				}
			}
		}
	}
	return false
}

func (s *messageManager) addHandler(n rawMessage, o rawMessage) {
	switch n.(type) {
	case *NodeMessage:
		m := n.(*NodeMessage)
		s.p2p.connect(m.Addresses)
		for k, v := range m.List {
			if t, ok := s.values[k]; ok && t.Managed && t.GetTimestamp() > v {
				s.sendMessage <- k
			}
		}
	case *AuthMessage:
	case *PeerMessage:
		s.handler(n, o)
	default:
		s.log.Debugf("uknown handler message at <%s>", n.GetDomain())
	}
}

func (s *messageManager) add(m rawMessage, force bool, save bool, managed bool) bool {
	//s.log.Debugf("add message at <%s>, force %t, save %t, managed %t", m.GetDomain(), force, save, managed)
	if !force && !s.verify(m) {
		s.log.Warnf("add message at <%s> failed, unauth.", m.GetDomain())
		return false
	}
	mm := message{rawMessage: m}
	if managed {
		mm.Managed = true
	}
	if v, ok := s.values[m.GetDomain()]; ok {
		s.addHandler(m, v.rawMessage)
	} else {
		s.addHandler(m, nil)
	}
	s.values[m.GetDomain()] = mm
	if save {
		mm.Message = m.Dump()
		mm.Type = reflect.TypeOf(m).String()
		if data, err := json.Marshal(mm); err != nil {
			s.log.Warnf("save message failed, %s", err)
			return false
		} else {
			if err := s.db.Put([]byte(m.GetDomain()), data, nil); err != nil {
				s.log.Warnf("save message failed, %s", err)
				return false
			}
		}
	}
	s.log.Debugf("add message at <%s> success", m.GetDomain())
	return true
}

func (s *messageManager) snapshot() map[string]int64 {
	snapshot := make(map[string]int64)
	for k, v := range s.values {
		snapshot[k] = v.GetTimestamp()
	}
	return snapshot
}

func (s *messageManager) heloMessage() bool {
	s.log.Debugf("send helo message.")
	node := NodeMessage{
		Domain:    s.Domain + "@",
		Addresses: s.Addresses,
		Timestamp: s.timestamp,
		List:      s.snapshot(),
	}
	m := message{
		rawMessage: &node,
	}
	m.sign(s.privateKey)
	return s.Set(m.rawMessage)
}

func (s *messageManager) heloLoop() {
	for {
		s.heloMessage()
		time.Sleep(30 * time.Second)
	}
}

func (s *messageManager) recvHandler(m *pubsub.Message) {
	if m.ReceivedFrom.String() == s.p2p.id {
		return
	} else {
		mm := s.loadFromByte(m.Data)
		if s.verify(mm) {
			s.mutex.Lock()
			defer s.mutex.Unlock()
			if om, ok := s.values[mm.GetDomain()]; ok {
				om := om.rawMessage
				if om.GetTimestamp() < mm.GetTimestamp() {
					s.log.Debugf("update message %s", mm.GetDomain())
					s.add(mm, false, true, false)
					return
				} else {
					s.log.Debugf("ignore old message %s", mm.GetDomain())
					return
				}
			} else {
				s.log.Debugf("add message %s", mm.GetDomain())
				s.add(mm, false, true, false)
				return
			}
		} else {
			s.log.Debugf("unauth message %s", mm.GetDomain())
			return
		}
	}
}

func (s *messageManager) recvLoop() {
	for {
		s.recvHandler(<-s.recvMessage)
	}
}

func (s *messageManager) Get(domain string) rawMessage {
	if v, ok := s.values[domain]; ok {
		return v.rawMessage
	}
	return nil
}

func (s *messageManager) Set(m rawMessage) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	mm := message{
		rawMessage: m,
	}

	if mm.GetSign() == "" {
		if mm.GetDomain() == s.Domain {
			mm.sign(s.privateKey)
		} else {
			s.log.Warnf("set unmanaged message %s", m.GetDomain())
			return false
		}
	}

	if s.verify(m) {
		if om, ok := s.values[mm.GetDomain()]; ok {
			if om.GetTimestamp() < mm.GetTimestamp() {
				s.log.Debugf("update message %s", mm.GetDomain())
				s.add(mm.rawMessage, false, true, false)
				s.sendMessage <- m.GetDomain()
				return true
			} else {
				s.log.Debugf("ignore old message %s", mm.GetDomain())
				return false
			}
		} else {
			s.log.Debugf("add message %s", mm.GetDomain())
			s.add(mm.rawMessage, false, true, false)
			s.sendMessage <- m.GetDomain()
			return true
		}
	} else {
		s.log.Warnf("set message verify failed. %s", m.GetDomain())
		return false
	}
}

func (s *messageManager) broadcast() {
	for {
		k := <-s.sendMessage
		s.mutex.Lock()
		defer s.mutex.Unlock()
		s.p2p.broadcast(s.values[k].rawMessage)
	}
}

func (s *messageManager) connectLoop() {
	for {
		s.p2p.connect(s.BootNode)
		for _, v := range s.values {
			domain := v.rawMessage.GetDomain()
			if domain[len(domain)-1] == '@' {
				node, ok := v.rawMessage.(*NodeMessage)
				if ok && node.Addresses != "" {
					s.p2p.connect(node.Addresses)
				}
			}
		}
		time.Sleep(30 * time.Second)
	}
}

func (s *messageManager) run() {
	s.p2p = (&p2p{
		privateKey:  s.PrivateKey,
		listen:      s.Listen,
		recvMessage: s.recvMessage,
	}).init(s.log)
	s.p2p.run()
	s.loadAllFromDB()

	go s.connectLoop()
	go s.broadcast()
	go s.heloLoop()
	go s.recvLoop()
	<-make(chan bool)
}
