package main

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"

	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

type execUpstreamRouteManager struct {
	runner func(ctx context.Context, name string, args ...string) *exec.Cmd
}

func newExecUpstreamRouteManager() *execUpstreamRouteManager {
	return &execUpstreamRouteManager{runner: exec.CommandContext}
}

func (m *execUpstreamRouteManager) EnsureRoutes(ctx context.Context, spec upstreamRouteSpec) error {
	if spec.Interface == "" {
		return fmt.Errorf("upstream route interface is required")
	}
	sourcePrefixes := append([]netip.Prefix(nil), spec.SourcePrefixes...)
	sort.Slice(sourcePrefixes, func(i, j int) bool { return netipPrefixLess(sourcePrefixes[i], sourcePrefixes[j]) })
	for _, source := range sourcePrefixes {
		if err := m.replaceAddress(ctx, spec.NetNS, spec.Interface, source); err != nil {
			return err
		}
	}
	sourceByFamily := upstreamSourceByFamily(sourcePrefixes)
	prefixes := append([]netip.Prefix(nil), spec.Prefixes...)
	sort.Slice(prefixes, func(i, j int) bool { return netipPrefixLess(prefixes[i], prefixes[j]) })
	for _, prefix := range prefixes {
		if err := m.replaceRoute(ctx, spec.NetNS, spec.Interface, prefix, sourceByFamily[prefix.Addr().Is4()]); err != nil {
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
	args := []string{family, "addr", "replace", prefix.String(), "dev", iface}
	return m.runIP(ctx, netnsName, args)
}

func (m *execUpstreamRouteManager) replaceRoute(ctx context.Context, netnsName, iface string, prefix netip.Prefix, source netip.Addr) error {
	family := "-6"
	if prefix.Addr().Is4() {
		family = "-4"
	}
	args := []string{family, "route", "replace", prefix.String(), "dev", iface, "proto", "static"}
	if source.IsValid() {
		args = append(args, "src", source.String())
	}
	return m.runIP(ctx, netnsName, args)
}

func (m *execUpstreamRouteManager) runIP(ctx context.Context, netnsName string, args []string) error {
	if netnsName != "" && netnsName != ipsec.NetNSHost {
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
