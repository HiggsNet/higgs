package main

import (
	"log"

	"github.com/miekg/dns"
	"github.com/peterzen/goresolver"
)

func main() {
	resolver, err := goresolver.NewResolver("/etc/resolv.conf")
	if err != nil {
		log.Fatal(err)
	}
	result, err := resolver.StrictNSQuery("www.catofes.com.", dns.TypeA)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(result)
}
