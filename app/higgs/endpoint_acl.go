package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/Catofes/higgs/pkg/firewall"
	"github.com/Catofes/higgs/pkg/routing"
	higgsservice "github.com/Catofes/higgs/pkg/service"
)

const (
	endpointACLScopePort = "port"
	endpointACLScopeIP   = "ip"
)

func applyEndpointACL(name, destination, scope, protocol string, port uint16, selectors []string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	acl, err := validateEndpointACL(endpointACL{Name: name, Destination: destination, Scope: scope, Protocol: protocol, Port: port, Selectors: selectors})
	if err != nil {
		return err
	}
	if ok, err := endpointACLApplyViaControl(rt, acl); err != nil {
		return err
	} else if !ok {
		return errors.New("endpoint ACL changes require a running Higgs daemon")
	}
	fmt.Printf("applied endpoint ACL %s\n", acl.Name)
	return nil
}

func removeEndpointACL(name string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if ok, err := endpointACLRemoveViaControl(rt, name); err != nil {
		return err
	} else if !ok {
		return errors.New("endpoint ACL changes require a running Higgs daemon")
	}
	fmt.Printf("removed endpoint ACL %s\n", name)
	return nil
}

func listEndpointACLs() error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	acls, ok, err := endpointACLListViaControl(rt)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("endpoint ACL listing requires a running Higgs daemon")
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(acls)
}

func validateEndpointACL(acl endpointACL) (endpointACL, error) {
	acl.Name = strings.TrimSpace(acl.Name)
	acl.Scope = strings.ToLower(strings.TrimSpace(acl.Scope))
	acl.Protocol = strings.ToLower(strings.TrimSpace(acl.Protocol))
	if _, err := higgsservice.NormalizeID(acl.Name); err != nil {
		return endpointACL{}, fmt.Errorf("endpoint ACL name: %w", err)
	}
	address, err := netip.ParseAddr(acl.Destination)
	if err != nil {
		return endpointACL{}, fmt.Errorf("endpoint ACL destination: %w", err)
	}
	acl.Destination = address.Unmap().String()
	if acl.Scope == "" {
		acl.Scope = endpointACLScopePort
	}
	switch acl.Scope {
	case endpointACLScopeIP:
		if acl.Protocol != "" || acl.Port != 0 {
			return endpointACL{}, errors.New("IP-scope endpoint ACL must not specify protocol or port")
		}
	case endpointACLScopePort:
		if acl.Protocol != firewall.ProtoTCP && acl.Protocol != firewall.ProtoUDP {
			return endpointACL{}, errors.New("port-scope endpoint ACL protocol must be tcp or udp")
		}
		if acl.Port == 0 {
			return endpointACL{}, errors.New("port-scope endpoint ACL port is required")
		}
	default:
		return endpointACL{}, errors.New("endpoint ACL scope must be ip or port")
	}
	if len(acl.Selectors) == 0 {
		return endpointACL{}, errors.New("endpoint ACL requires at least one selector; omit the ACL for an unrestricted endpoint")
	}
	seen := map[string]bool{}
	selectors := make([]string, 0, len(acl.Selectors))
	for _, raw := range acl.Selectors {
		selector, err := higgsservice.ParseZoneSelector(raw)
		if err != nil {
			return endpointACL{}, err
		}
		value := selector.String()
		if !seen[value] {
			seen[value] = true
			selectors = append(selectors, value)
		}
	}
	sort.Strings(selectors)
	acl.Selectors = selectors
	return acl, nil
}

func resolveEndpointServices(acls map[string]endpointACL, ars *routing.AuthorizedRouteSet) ([]firewall.EndpointService, error) {
	if len(acls) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(acls))
	for name := range acls {
		names = append(names, name)
	}
	sort.Strings(names)
	services := make([]firewall.EndpointService, 0, len(names))
	for _, name := range names {
		acl, err := validateEndpointACL(acls[name])
		if err != nil {
			return nil, fmt.Errorf("endpoint ACL %s: %w", name, err)
		}
		var selectors []higgsservice.ZoneSelector
		for _, raw := range acl.Selectors {
			selector, _ := higgsservice.ParseZoneSelector(raw)
			selectors = append(selectors, selector)
		}
		var sources []netip.Prefix
		if ars != nil {
			for sourceZone, routes := range ars.Announced {
				matched := false
				for _, selector := range selectors {
					if selector.Matches(sourceZone) {
						matched = true
						break
					}
				}
				if matched {
					for prefix := range routes {
						sources = append(sources, prefix)
					}
				}
			}
		}
		address, _ := netip.ParseAddr(acl.Destination)
		familySources := sources[:0]
		for _, prefix := range sources {
			if prefix.Addr().Is4() == address.Is4() {
				familySources = append(familySources, prefix)
			}
		}
		services = append(services, firewall.EndpointService{
			Name: acl.Name, Proto: acl.Protocol, Port: acl.Port,
			Destination: address, Sources: canonicalEndpointPrefixes(familySources),
		})
	}
	return services, nil
}

func canonicalEndpointPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	seen := map[string]bool{}
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		if !seen[prefix.String()] {
			seen[prefix.String()] = true
			out = append(out, prefix)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func (d *DaemonService) handleEndpointACLApplyEvent(acl endpointACL) error {
	validated, err := validateEndpointACL(acl)
	if err != nil {
		return err
	}
	if !d.hasEnforcingHostFirewall() {
		return errors.New("endpoint ACL requires an enabled managed host firewall instance with an available nftables or iptables backend")
	}
	snapshot, _, _ := d.snapshotState()
	if snapshot == nil || snapshot.Network == nil {
		return errors.New("daemon state is not loaded")
	}
	ars, err := routing.BuildAuthorizedRouteSet(snapshot.Network, d.Sync.now())
	if err != nil {
		return fmt.Errorf("build route authorization: %w", err)
	}
	destination, _ := netip.ParseAddr(validated.Destination)
	owned := false
	for _, assignment := range ars.AllAssignments {
		if assignment.AssignedTo == snapshot.ManagedZone && assignment.Prefix.Contains(destination) {
			owned = true
			break
		}
	}
	if !owned {
		return fmt.Errorf("endpoint ACL destination %s is outside the managed Zone's active assignments", destination)
	}
	return d.runStateStoreWrite(func(state *stateFile) error {
		if state.EndpointACLs == nil {
			state.EndpointACLs = make(map[string]endpointACL)
		}
		state.EndpointACLs[validated.Name] = validated
		return nil
	})
}

func (d *DaemonService) handleEndpointACLRemoveEvent(name string) error {
	name, err := higgsservice.NormalizeID(name)
	if err != nil {
		return err
	}
	return d.runStateStoreWrite(func(state *stateFile) error {
		delete(state.EndpointACLs, name)
		return nil
	})
}

func (d *DaemonService) hasEnforcingHostFirewall() bool {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return false
	}
	preflight := firewall.PreflightProbe(context.Background())
	for _, instance := range firewallInstancesEnabled(d.Sync.App.Config) {
		if instance.IsHost && instance.Mode == firewall.ModeManaged && instance.Backend != firewall.BackendNone {
			if d.firewallDriver != nil {
				return true
			}
			backend, err := firewall.ResolveBackendForInstance(firewall.FirewallInstanceSpec{
				ID: instance.ID, Backend: instance.Backend, NativeHooks: instance.NativeHooks,
			}, preflight)
			if err != nil {
				continue
			}
			if backend == firewall.BackendNFT || backend == firewall.BackendIptables {
				return true
			}
		}
	}
	return false
}
