package photonlinux

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"

	"github.com/HiggsNet/photon/pkg/routing/bird"
	transportipsec "github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type UpstreamRouteSpec struct {
	NetNS          string
	Interface      string
	Prefixes       []netip.Prefix
	SourcePrefixes []netip.Prefix
	MeshIPv4LL     string
	MeshIPv6LL     string
}

type UpstreamRouteManager interface {
	EnsureRoutes(context.Context, UpstreamRouteSpec) error
}

func (r *Runtime) EnsureRoutingVeth(ctx context.Context, spec bird.VethSpec) error {
	if r == nil || r.vethManager == nil {
		return fmt.Errorf("linux routing runtime is not configured")
	}
	return r.vethManager.EnsureVethPair(ctx, spec)
}

func (r *Runtime) EnsureUpstreamRoutes(ctx context.Context, spec UpstreamRouteSpec) error {
	if r == nil || r.upstreamRoutes == nil {
		return fmt.Errorf("linux routing runtime is not configured")
	}
	return r.upstreamRoutes.EnsureRoutes(ctx, spec)
}

type execUpstreamRouteManager struct {
	runner func(ctx context.Context, name string, args ...string) *exec.Cmd
}

func newExecUpstreamRouteManager() *execUpstreamRouteManager {
	return &execUpstreamRouteManager{runner: exec.CommandContext}
}

func (m *execUpstreamRouteManager) EnsureRoutes(ctx context.Context, spec UpstreamRouteSpec) error {
	if spec.Interface == "" {
		return fmt.Errorf("upstream route interface is required")
	}
	sourcePrefixes := append([]netip.Prefix(nil), spec.SourcePrefixes...)
	sort.Slice(sourcePrefixes, func(i, j int) bool { return prefixLess(sourcePrefixes[i], sourcePrefixes[j]) })
	for _, source := range sourcePrefixes {
		if err := m.replaceAddress(ctx, spec.NetNS, spec.Interface, source); err != nil {
			return err
		}
	}
	nextHopByFamily, err := upstreamNextHopByFamily(spec.MeshIPv4LL, spec.MeshIPv6LL)
	if err != nil {
		return err
	}
	sourceByFamily := upstreamSourceByFamily(sourcePrefixes)
	prefixes := append([]netip.Prefix(nil), spec.Prefixes...)
	sort.Slice(prefixes, func(i, j int) bool { return prefixLess(prefixes[i], prefixes[j]) })
	for _, prefix := range prefixes {
		is4 := prefix.Addr().Is4()
		if err := m.replaceRoute(ctx, spec.NetNS, spec.Interface, prefix, sourceByFamily[is4], nextHopByFamily[is4]); err != nil {
			return err
		}
	}
	return nil
}

func (m *execUpstreamRouteManager) replaceAddress(ctx context.Context, netnsName, iface string, prefix netip.Prefix) error {
	family := "-6"
	if prefix.Addr().Is4() {
		family = "-4"
	}
	return m.runIP(ctx, netnsName, []string{family, "addr", "replace", prefix.String(), "dev", iface})
}

func (m *execUpstreamRouteManager) replaceRoute(ctx context.Context, netnsName, iface string, prefix netip.Prefix, source netip.Addr, nextHop netip.Addr) error {
	family := "-6"
	if prefix.Addr().Is4() {
		family = "-4"
	}
	args := []string{family, "route", "replace", prefix.String(), "dev", iface, "proto", "static"}
	if nextHop.IsValid() {
		args = append(args, "via", nextHop.String())
	}
	if source.IsValid() {
		args = append(args, "src", source.String())
	}
	return m.runIP(ctx, netnsName, args)
}

func (m *execUpstreamRouteManager) runIP(ctx context.Context, netnsName string, args []string) error {
	if netnsName != "" && netnsName != transportipsec.NetNSHost {
		args = append([]string{"netns", "exec", netnsName, "ip"}, args...)
	}
	cmd := m.runner(ctx, "ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func upstreamSourceByFamily(prefixes []netip.Prefix) map[bool]netip.Addr {
	out := make(map[bool]netip.Addr, 2)
	for _, prefix := range prefixes {
		is4 := prefix.Addr().Is4()
		if _, ok := out[is4]; !ok {
			out[is4] = prefix.Addr()
		}
	}
	return out
}

func upstreamNextHopByFamily(ipv4LL, ipv6LL string) (map[bool]netip.Addr, error) {
	out := make(map[bool]netip.Addr, 2)
	if ipv4LL != "" {
		prefix, err := netip.ParsePrefix(ipv4LL)
		if err != nil {
			return nil, fmt.Errorf("invalid mesh ipv4_ll %q: %w", ipv4LL, err)
		}
		out[true] = prefix.Addr()
	}
	if ipv6LL != "" {
		prefix, err := netip.ParsePrefix(ipv6LL)
		if err != nil {
			return nil, fmt.Errorf("invalid mesh ipv6_ll %q: %w", ipv6LL, err)
		}
		out[false] = prefix.Addr()
	}
	return out, nil
}

func prefixLess(left, right netip.Prefix) bool {
	if left.Addr().Less(right.Addr()) {
		return true
	}
	if right.Addr().Less(left.Addr()) {
		return false
	}
	return left.Bits() < right.Bits()
}
