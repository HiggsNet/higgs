package ipsec

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type dnsLookupResult struct {
	addresses []net.IPAddr
	err       error
}

type sequenceDNSResolver struct {
	results []dnsLookupResult
	calls   int
}

func (r *sequenceDNSResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	index := r.calls
	r.calls++
	if index >= len(r.results) {
		index = len(r.results) - 1
	}
	result := r.results[index]
	return cloneIPAddrs(result.addresses), result.err
}

func TestDNSFamilyHoldDownExpiresMissingIPv6AfterConsecutiveMisses(t *testing.T) {
	now := time.Unix(1717171717, 0)
	dual := dnsTestAddresses("198.51.100.20", "2001:db8::20")
	v4Only := dnsTestAddresses("198.51.100.20")
	upstream := &sequenceDNSResolver{results: []dnsLookupResult{
		{addresses: dual},
		{addresses: v4Only},
		{addresses: v4Only},
		{addresses: v4Only},
	}}
	resolver := NewDNSFamilyHoldDownResolver(upstream, DNSFamilyHoldDownOptions{
		Grace:                time.Hour,
		MinConsecutiveMisses: 3,
		Now:                  func() time.Time { return now },
	})

	assertDNSFamilies(t, lookupDNS(t, resolver), true, true)
	now = now.Add(time.Minute)
	assertDNSFamilies(t, lookupDNS(t, resolver), true, true)
	now = now.Add(time.Minute)
	assertDNSFamilies(t, lookupDNS(t, resolver), true, true)
	now = now.Add(time.Minute)
	assertDNSFamilies(t, lookupDNS(t, resolver), true, false)
}

func TestDNSFamilyHoldDownExpiresMissingIPv6AfterGrace(t *testing.T) {
	now := time.Unix(1717171717, 0)
	upstream := &sequenceDNSResolver{results: []dnsLookupResult{
		{addresses: dnsTestAddresses("198.51.100.20", "2001:db8::20")},
		{addresses: dnsTestAddresses("198.51.100.20")},
	}}
	resolver := NewDNSFamilyHoldDownResolver(upstream, DNSFamilyHoldDownOptions{
		Grace:                5 * time.Minute,
		MinConsecutiveMisses: 100,
		Now:                  func() time.Time { return now },
	})

	assertDNSFamilies(t, lookupDNS(t, resolver), true, true)
	now = now.Add(5 * time.Minute)
	assertDNSFamilies(t, lookupDNS(t, resolver), true, false)
}

func TestDNSFamilyHoldDownRecoveryResetsConsecutiveMisses(t *testing.T) {
	now := time.Unix(1717171717, 0)
	dual := dnsTestAddresses("198.51.100.20", "2001:db8::20")
	v4Only := dnsTestAddresses("198.51.100.20")
	upstream := &sequenceDNSResolver{results: []dnsLookupResult{
		{addresses: dual},
		{addresses: v4Only},
		{addresses: v4Only},
		{addresses: dual},
		{addresses: v4Only},
	}}
	resolver := NewDNSFamilyHoldDownResolver(upstream, DNSFamilyHoldDownOptions{
		Grace:                time.Hour,
		MinConsecutiveMisses: 3,
		Now:                  func() time.Time { return now },
	})

	for range 4 {
		assertDNSFamilies(t, lookupDNS(t, resolver), true, true)
		now = now.Add(time.Minute)
	}
	now = now.Add(10 * time.Minute)
	// A successful dual-stack answer reset the two earlier misses, so one new
	// miss is not enough to retire the family.
	assertDNSFamilies(t, lookupDNS(t, resolver), true, true)
}

func TestDNSFamilyHoldDownServesCacheForTransientErrorButNotCancellation(t *testing.T) {
	now := time.Unix(1717171717, 0)
	temporaryErr := errors.New("temporary resolver failure")
	upstream := &sequenceDNSResolver{results: []dnsLookupResult{
		{addresses: dnsTestAddresses("198.51.100.20", "2001:db8::20")},
		{err: temporaryErr},
		{err: context.Canceled},
	}}
	resolver := NewDNSFamilyHoldDownResolver(upstream, DNSFamilyHoldDownOptions{
		Now: func() time.Time { return now },
	})

	assertDNSFamilies(t, lookupDNS(t, resolver), true, true)
	addresses, err := resolver.LookupIPAddr(context.Background(), "node.example.com")
	if err != nil {
		t.Fatalf("transient cached lookup error = %v", err)
	}
	assertDNSFamilies(t, addresses, true, true)
	if _, err := resolver.LookupIPAddr(context.Background(), "node.example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lookup error = %v, want context canceled", err)
	}
}

func lookupDNS(t *testing.T, resolver DNSResolver) []net.IPAddr {
	t.Helper()
	addresses, err := resolver.LookupIPAddr(context.Background(), "node.example.com")
	if err != nil {
		t.Fatalf("LookupIPAddr: %v", err)
	}
	return addresses
}

func dnsTestAddresses(values ...string) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(values))
	for _, value := range values {
		out = append(out, net.IPAddr{IP: net.ParseIP(value)})
	}
	return out
}

func assertDNSFamilies(t *testing.T, addresses []net.IPAddr, want4, want6 bool) {
	t.Helper()
	var got4, got6 bool
	for _, address := range addresses {
		switch dnsIPFamily(address.IP) {
		case FamilyIPv4:
			got4 = true
		case FamilyIPv6:
			got6 = true
		}
	}
	if got4 != want4 || got6 != want6 {
		t.Fatalf("families = ipv4:%t ipv6:%t, want ipv4:%t ipv6:%t; addresses=%v", got4, got6, want4, want6, addresses)
	}
}
