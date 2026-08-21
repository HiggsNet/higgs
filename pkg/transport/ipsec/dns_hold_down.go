package ipsec

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	DefaultDNSFamilyHoldDownGrace  = 5 * time.Minute
	DefaultDNSFamilyHoldDownMisses = 3
)

// DNSFamilyHoldDownOptions controls how long a previously resolved address
// family survives incomplete DNS answers. A cached family is retired after
// either the grace period or the consecutive-miss threshold is reached.
type DNSFamilyHoldDownOptions struct {
	Grace                time.Duration
	MinConsecutiveMisses int
	Now                  func() time.Time
}

// DNSFamilyHoldDownResolver preserves the last successful result for an
// address family when an otherwise successful dual-stack lookup temporarily
// returns only A or only AAAA records. It also serves cached results for
// transient resolver errors, but never masks context cancellation.
type DNSFamilyHoldDownResolver struct {
	upstream DNSResolver
	grace    time.Duration
	misses   int
	now      func() time.Time

	mu    sync.Mutex
	hosts map[string]map[string]*dnsFamilyCacheEntry
}

type dnsFamilyCacheEntry struct {
	addresses         []net.IPAddr
	lastSuccess       time.Time
	consecutiveMisses int
}

func NewDNSFamilyHoldDownResolver(upstream DNSResolver, opts DNSFamilyHoldDownOptions) *DNSFamilyHoldDownResolver {
	if upstream == nil {
		upstream = net.DefaultResolver
	}
	if opts.Grace <= 0 {
		opts.Grace = DefaultDNSFamilyHoldDownGrace
	}
	if opts.MinConsecutiveMisses <= 0 {
		opts.MinConsecutiveMisses = DefaultDNSFamilyHoldDownMisses
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &DNSFamilyHoldDownResolver{
		upstream: upstream,
		grace:    opts.Grace,
		misses:   opts.MinConsecutiveMisses,
		now:      opts.Now,
		hosts:    make(map[string]map[string]*dnsFamilyCacheEntry),
	}
}

func (r *DNSFamilyHoldDownResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if r == nil || r.upstream == nil {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}
	resolved, lookupErr := r.upstream.LookupIPAddr(ctx, host)
	if errors.Is(lookupErr, context.Canceled) || errors.Is(lookupErr, context.DeadlineExceeded) {
		return nil, lookupErr
	}

	now := r.now()
	key := canonicalDNSHost(host)
	current := splitDNSFamilies(resolved)

	r.mu.Lock()
	defer r.mu.Unlock()
	families := r.hosts[key]
	if families == nil {
		families = make(map[string]*dnsFamilyCacheEntry)
		r.hosts[key] = families
	}

	for family, addresses := range current {
		families[family] = &dnsFamilyCacheEntry{
			addresses:   cloneIPAddrs(addresses),
			lastSuccess: now,
		}
	}

	out := cloneIPAddrs(resolved)
	for _, family := range []string{FamilyIPv4, FamilyIPv6} {
		if len(current[family]) > 0 {
			continue
		}
		cached := families[family]
		if cached == nil {
			continue
		}
		cached.consecutiveMisses++
		if r.dnsFamilyHoldExpired(cached, now) {
			delete(families, family)
			continue
		}
		out = append(out, cloneIPAddrs(cached.addresses)...)
	}
	if len(families) == 0 {
		delete(r.hosts, key)
	}
	if len(out) > 0 {
		return out, nil
	}
	return nil, lookupErr
}

func (r *DNSFamilyHoldDownResolver) dnsFamilyHoldExpired(entry *dnsFamilyCacheEntry, now time.Time) bool {
	if entry == nil {
		return false
	}
	return entry.consecutiveMisses >= r.misses || !now.Before(entry.lastSuccess.Add(r.grace))
}

func splitDNSFamilies(addresses []net.IPAddr) map[string][]net.IPAddr {
	out := make(map[string][]net.IPAddr, 2)
	for _, address := range addresses {
		family := dnsIPFamily(address.IP)
		if family == "" {
			continue
		}
		out[family] = append(out[family], cloneIPAddr(address))
	}
	return out
}

func dnsIPFamily(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return FamilyIPv4
	}
	if ip.To16() != nil {
		return FamilyIPv6
	}
	return ""
}

func canonicalDNSHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func cloneIPAddrs(in []net.IPAddr) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(in))
	for _, address := range in {
		out = append(out, cloneIPAddr(address))
	}
	return out
}

func cloneIPAddr(in net.IPAddr) net.IPAddr {
	return net.IPAddr{IP: append(net.IP(nil), in.IP...), Zone: in.Zone}
}
