package firewall

import (
	"net/netip"
	"testing"
)

func TestBuildForwardingPolicy(t *testing.T) {
	p := BuildForwardingPolicy(true,
		[]netip.Prefix{mustPrefix(t, "10.0.0.0/8")},
		[]netip.Prefix{mustPrefix(t, "10.99.0.0/24")},
		[]string{"*.catofes."},
		[]string{},
		200,
	)
	if !p.Transit {
		t.Error("transit should be true")
	}
	if !IsTransitPrefixAllowed(p, mustPrefix(t, "10.42.0.0/24")) {
		t.Error("10.42/16 should be allowed under 10/8 allow")
	}
	if IsTransitPrefixAllowed(p, mustPrefix(t, "10.99.0.0/24")) {
		t.Error("10.99/24 should be denied")
	}
}
