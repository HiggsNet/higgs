package higgs

// import (
// 	"sync"
// )

// type Peer struct {
// 	Name      string
// 	Domain    string
// 	Infos     map[string]string
// 	callbacks map[string]func(string) bool
// 	dnssec    bool
// 	mutex     sync.Mutex
// }

// func (s *Peer) Init(name, domain string, dnssec bool) *Peer {
// 	s.Name = name
// 	s.Domain = domain
// 	s.dnssec = dnssec
// 	s.Infos = make(map[string]string)
// 	s.callbacks = make(map[string]func(string) bool)
// 	s.mutex = sync.Mutex{}
// 	return s
// }
