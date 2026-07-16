package main

import (
	"fmt"
	"net/netip"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
	higgsservice "github.com/Catofes/higgs/pkg/service"
)

type resolvedServiceNetwork struct {
	Config         serviceNetworkConfig
	IPv4           *serviceNetworkIPAMConfig
	IPv6           *serviceNetworkIPAMConfig
	IPv4Assignment *routing.AssignmentEntry
	IPv6Assignment *routing.AssignmentEntry
}

func resolveServiceNetworks(configured []serviceNetworkConfig, owner zone.ZonePath, ars *routing.AuthorizedRouteSet) (map[string]resolvedServiceNetwork, error) {
	result := make(map[string]resolvedServiceNetwork, len(configured))
	var all []resolvedServiceNetwork
	for _, network := range configured {
		resolved := resolvedServiceNetwork{Config: network}
		if network.IPv4 != nil {
			ipam, assignment, err := resolveServiceNetworkPlan(*network.IPv4, owner, ars)
			if err != nil {
				return nil, fmt.Errorf("network %s ipv4: %w", network.ID, err)
			}
			resolved.IPv4, resolved.IPv4Assignment = &ipam, assignment
		}
		if network.IPv6 != nil {
			ipam, assignment, err := resolveServiceNetworkPlan(*network.IPv6, owner, ars)
			if err != nil {
				return nil, fmt.Errorf("network %s ipv6: %w", network.ID, err)
			}
			resolved.IPv6, resolved.IPv6Assignment = &ipam, assignment
		}
		for _, previous := range all {
			if resolved.IPv4 != nil && previous.IPv4 != nil && resolved.IPv4.Subnet.Overlaps(previous.IPv4.Subnet) {
				return nil, fmt.Errorf("network %s ipv4 subnet %s overlaps network %s subnet %s", network.ID, resolved.IPv4.Subnet, previous.Config.ID, previous.IPv4.Subnet)
			}
			if resolved.IPv6 != nil && previous.IPv6 != nil && resolved.IPv6.Subnet.Overlaps(previous.IPv6.Subnet) {
				return nil, fmt.Errorf("network %s ipv6 subnet %s overlaps network %s subnet %s", network.ID, resolved.IPv6.Subnet, previous.Config.ID, previous.IPv6.Subnet)
			}
		}
		all = append(all, resolved)
		result[network.ID] = resolved
	}
	return result, nil
}

func resolveServiceNetworkPlan(plan serviceNetworkAddressPlan, owner zone.ZonePath, ars *routing.AuthorizedRouteSet) (serviceNetworkIPAMConfig, *routing.AssignmentEntry, error) {
	switch plan.Source {
	case serviceNetworkSourceLocal:
		resolved, err := materializeServiceNetworkPlan(plan, netip.Prefix{})
		return resolved, nil, err
	case serviceNetworkSourceShared:
		return serviceNetworkIPAMConfig{}, nil, fmt.Errorf("shared source is reserved for Phase 8.6 and is not supported yet")
	case serviceNetworkSourceLegacy:
		resolved, err := materializeServiceNetworkPlan(plan, netip.Prefix{})
		if err != nil {
			return serviceNetworkIPAMConfig{}, nil, err
		}
		assignment, err := higgsservice.AuthorizeNetworkPrefix(owner, resolved.Subnet, ars)
		return resolved, assignment, err
	case serviceNetworkSourceAssignment:
		assignment := findExactServiceAssignment(owner, plan.Assignment, ars)
		if assignment == nil {
			return serviceNetworkIPAMConfig{}, nil, fmt.Errorf("service_network_unauthorized: assignment %s is not an active non-shared assignment to %s", plan.Assignment, owner)
		}
		resolved, err := materializeServiceNetworkPlan(plan, assignment.Prefix)
		return resolved, assignment, err
	case serviceNetworkSourceAuto:
		if ars == nil {
			return serviceNetworkIPAMConfig{}, nil, fmt.Errorf("service authorization set is nil")
		}
		type candidate struct {
			ipam       serviceNetworkIPAMConfig
			assignment *routing.AssignmentEntry
		}
		var candidates []candidate
		for _, assignment := range ars.AllAssignments {
			if assignment == nil || assignment.Shared || assignment.AssignedTo != owner || addressFamily(assignment.Prefix.Addr()) != plan.Family {
				continue
			}
			resolved, err := materializeServiceNetworkPlan(plan, assignment.Prefix)
			if err == nil {
				candidates = append(candidates, candidate{ipam: resolved, assignment: assignment})
			}
		}
		if len(candidates) == 0 {
			return serviceNetworkIPAMConfig{}, nil, fmt.Errorf("service_network_unauthorized: auto found no active non-shared IPv%d assignment to %s that can contain the network", plan.Family, owner)
		}
		if len(candidates) > 1 {
			return serviceNetworkIPAMConfig{}, nil, fmt.Errorf("auto is ambiguous: found %d active non-shared IPv%d assignments to %s; use assignment:<CIDR>", len(candidates), plan.Family, owner)
		}
		return candidates[0].ipam, candidates[0].assignment, nil
	default:
		return serviceNetworkIPAMConfig{}, nil, fmt.Errorf("unknown network source %q", plan.Source)
	}
}

func materializeServiceNetworkPlan(plan serviceNetworkAddressPlan, base netip.Prefix) (serviceNetworkIPAMConfig, error) {
	subnet, err := resolveServicePrefixExpr(base, plan.Subnet)
	if err != nil {
		return serviceNetworkIPAMConfig{}, fmt.Errorf("subnet: %w", err)
	}
	ipRange, err := resolveServicePrefixExpr(base, plan.IPRange)
	if err != nil {
		return serviceNetworkIPAMConfig{}, fmt.Errorf("dynamic range: %w", err)
	}
	gateway, err := resolveServiceAddrExpr(base, plan.Gateway)
	if err != nil {
		return serviceNetworkIPAMConfig{}, fmt.Errorf("gateway: %w", err)
	}
	if base.IsValid() && !prefixContainsPrefix(base, subnet) {
		return serviceNetworkIPAMConfig{}, fmt.Errorf("subnet %s is outside assignment %s", subnet, base)
	}
	if ipRange.IsValid() && !prefixContainsPrefix(subnet, ipRange) {
		return serviceNetworkIPAMConfig{}, fmt.Errorf("dynamic range %s must be contained by subnet %s", ipRange, subnet)
	}
	if !subnet.Contains(gateway) || gateway == subnet.Addr() {
		return serviceNetworkIPAMConfig{}, fmt.Errorf("gateway %s must be a usable address in subnet %s", gateway, subnet)
	}
	return serviceNetworkIPAMConfig{Subnet: subnet, IPRange: ipRange, Gateway: gateway}, nil
}

func resolveServicePrefixExpr(base netip.Prefix, expr servicePrefixExpr) (netip.Prefix, error) {
	if !expr.Relative {
		return expr.Prefix, nil
	}
	if !base.IsValid() {
		return netip.Prefix{}, fmt.Errorf("relative prefix requires an assignment")
	}
	addr, err := addServiceAddress(base.Masked().Addr(), expr.Prefix.Addr())
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, expr.Prefix.Bits()).Masked(), nil
}

func resolveServiceAddrExpr(base netip.Prefix, expr serviceAddrExpr) (netip.Addr, error) {
	if !expr.Relative {
		return expr.Addr, nil
	}
	if !base.IsValid() {
		return netip.Addr{}, fmt.Errorf("relative address requires an assignment")
	}
	return addServiceAddress(base.Masked().Addr(), expr.Addr)
}

func resolveServiceInstanceAddress(spec serviceAddressSpec, network resolvedServiceNetwork) (netip.Addr, serviceNetworkIPAMConfig, *routing.AssignmentEntry, error) {
	addr := spec.Addr
	if spec.Relative {
		if network.IPv6 == nil {
			return netip.Addr{}, serviceNetworkIPAMConfig{}, nil, fmt.Errorf("relative IPv6 address requires network ipv6")
		}
		var err error
		addr, err = addServiceAddress(network.IPv6.Subnet.Masked().Addr(), spec.Addr)
		if err != nil {
			return netip.Addr{}, serviceNetworkIPAMConfig{}, nil, err
		}
	}
	var ipam *serviceNetworkIPAMConfig
	var assignment *routing.AssignmentEntry
	if addr.Is4() {
		ipam, assignment = network.IPv4, network.IPv4Assignment
	} else {
		ipam, assignment = network.IPv6, network.IPv6Assignment
	}
	if ipam == nil {
		return netip.Addr{}, serviceNetworkIPAMConfig{}, nil, fmt.Errorf("address %s has no matching network family", addr)
	}
	if !ipam.Subnet.Contains(addr) {
		return netip.Addr{}, serviceNetworkIPAMConfig{}, nil, fmt.Errorf("address %s is outside network subnet %s", addr, ipam.Subnet)
	}
	if addr == ipam.Gateway {
		return netip.Addr{}, serviceNetworkIPAMConfig{}, nil, fmt.Errorf("address %s conflicts with network gateway", addr)
	}
	if ipam.IPRange.IsValid() && ipam.IPRange.Contains(addr) {
		return netip.Addr{}, serviceNetworkIPAMConfig{}, nil, fmt.Errorf("address %s is inside Docker dynamic range %s; use a static address outside the range", addr, ipam.IPRange)
	}
	return addr, *ipam, assignment, nil
}

func findExactServiceAssignment(owner zone.ZonePath, prefix netip.Prefix, ars *routing.AuthorizedRouteSet) *routing.AssignmentEntry {
	if ars == nil {
		return nil
	}
	for _, assignment := range ars.AllAssignments {
		if assignment != nil && !assignment.Shared && assignment.AssignedTo == owner && assignment.Prefix == prefix {
			return assignment
		}
	}
	return nil
}

func addServiceAddress(base, offset netip.Addr) (netip.Addr, error) {
	if base.Is4() != offset.Is4() {
		return netip.Addr{}, fmt.Errorf("address families do not match")
	}
	if base.Is4() {
		b, o := base.As4(), offset.As4()
		var out [4]byte
		carry := 0
		for i := 3; i >= 0; i-- {
			sum := int(b[i]) + int(o[i]) + carry
			out[i], carry = byte(sum), sum>>8
		}
		if carry != 0 {
			return netip.Addr{}, fmt.Errorf("relative address overflows IPv4")
		}
		return netip.AddrFrom4(out), nil
	}
	b, o := base.As16(), offset.As16()
	var out [16]byte
	carry := 0
	for i := 15; i >= 0; i-- {
		sum := int(b[i]) + int(o[i]) + carry
		out[i], carry = byte(sum), sum>>8
	}
	if carry != 0 {
		return netip.Addr{}, fmt.Errorf("relative address overflows IPv6")
	}
	return netip.AddrFrom16(out), nil
}

func addressFamily(addr netip.Addr) int {
	if addr.Is4() {
		return 4
	}
	return 6
}
