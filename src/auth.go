package higgs

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

type AuthMessage struct {
	Domain    string `hcl:"Domain,attr"`
	Key       string `hcl:"Key,attr"`
	Sign      string `hcl:"Sign,attr"`
	Timestamp int64  `hcl:"Timestamp,attr"`
	key       ed25519.PublicKey
	managed   bool
}

func (s *AuthMessage) getDomain() string {
	return s.Domain
}

func (s *AuthMessage) getMessage() string {
	if d, err := json.Marshal(
		&AuthMessage{
			Domain:    s.Domain,
			Key:       s.Key,
			Timestamp: s.Timestamp,
		}); err == nil {
		return string(d)
	}
	return ""
}

func (s *AuthMessage) getSign() string {
	return s.Sign
}

func (s *AuthMessage) setSign(sign string) {
	s.Sign = sign
}

func (s *AuthMessage) getKey() ed25519.PublicKey {
	if s.key == nil {
		s.key = ParsePublicKey(s.Key)
	}
	return s.key
}

func (s *AuthMessage) dump() string {
	data, _ := json.Marshal(s)
	return string(data)
}

func (s *AuthMessage) load(input string) error {
	return json.Unmarshal([]byte(input), s)
}

type authManager struct {
	authes     map[string]AuthMessage
	manageKey  ed25519.PrivateKey
	privateKey ed25519.PrivateKey
	mutex      sync.Mutex
	db         *leveldb.DB
}

func (s *authManager) init(db *leveldb.DB, p2p *p2p) *authManager {
	s.db = db
	s.privateKey = ParsePrivateKey(p2p.PrivateKey)
	if p2p.ManageKey != "" {
		s.manageKey = ParsePrivateKey(p2p.ManageKey)
	} else {
		s.manageKey = nil
	}
	s.authes = make(map[string]AuthMessage)
	s.authes["."] = AuthMessage{
		Domain:    ".",
		Key:       p2p.TrustCA,
		Timestamp: time.Now().UnixNano(),
	}
	for _, v := range p2p.Auth {
		s.add(v, true)
	}
	return s
}

func (s *authManager) loadFromDB(domain string) bool {
	domain = strings.Trim(domain, ".")
	if data, err := s.db.Get([]byte(domain), nil); err == nil {
		auth := AuthMessage{}
		if err := json.Unmarshal(data, &auth); err != nil {
			return false
		}
		if s.addWithoutMutex(auth, false) {
			return true
		} else {
			s.db.Delete([]byte(domain), nil)
		}
	}
	return false
}

func (s *authManager) verify(m message) bool {
	domain := m.getDomain()
	if domain == "." {
		return true
	}
	domains := strings.Split(domain, ".")
	for i := 1; i < len(domains); i++ {
		domain := strings.Join(domains[i:], ".") + "."
		if a, ok := s.authes[domain]; ok {
			if m.verify(a.getKey()) {
				return true
			}
		} else {
			if s.loadFromDB(strings.Join(domains[i:], ".")) {
				if a, ok := s.authes[domain]; ok {

					if m.verify(a.getKey()) {
						return true
					}
				}
			}
		}
	}
	return false
}

func (s *authManager) save(a AuthMessage) error {
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	domain := strings.Trim(a.Domain, ".")
	return s.db.Put([]byte(domain), data, nil)
}

func (s *authManager) add(a AuthMessage, force bool) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.addWithoutMutex(a, force)
}

func (s *authManager) addWithoutMutex(a AuthMessage, force bool) bool {
	// m := message{&a}
	// if s.verify(m) || force {
	// 	if t, ok := s.authes[a.getDomain()]; ok {
	// 		if a.Timestamp > t.Timestamp {
	// 			s.authes[a.getDomain()] = a
	// 			s.save(a)
	// 			return true
	// 		}
	// 	} else {
	// 		s.authes[a.getDomain()] = a
	// 		s.save(a)
	// 		return true
	// 	}
	// }
	return false
}
