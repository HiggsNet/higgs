package resolver

import (
	"context"
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

type Handler func(*dns.RR) error

type data struct {
	dns.RR
	q dns.Question
	h Handler
	c context.Context
}

type Resolver struct {
	datas map[dns.Question]data
	mutex sync.Mutex
}

func (s *Resolver) Init() {
	s.datas = make(map[dns.Question]data)
}

func (s *Resolver) Get(name, qtype string) (*dns.RR, error) {
	t, ok := dns.StringToType[qtype]
	if !ok {
		return nil, fmt.Errorf("wrong dns type")
	}
	req := dns.Question{Name: dns.Fqdn(name), Qtype: t, Qclass: dns.ClassINET}
	if r, ok := s.datas[req]; ok {
		return &(r.RR), nil
	}
	return nil, fmt.Errorf("not found")
}

func (s *Resolver) Watch(name, qtype string, callback Handler) error {
	_, ok := dns.StringToType[qtype]
	if !ok {
		return fmt.Errorf("wrong dns type")
	}
	if v, _ := s.Get(name, qtype); v != nil {
		return fmt.Errorf("already watched")
	}
	return nil
}

func (s *data) loop() {
	if s.q.Name == "" {
		return
	}
}
