package resolver

import "github.com/miekg/dns"

type CacheClient struct {
	dns.Client
	Server []string
	cache  map[dns.Question][]dns.RR
}

func (s *CacheClient) Init() {

}
