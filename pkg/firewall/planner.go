package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const (
	ModeManaged  = "managed"
	ModeExternal = "external"
	ModeDisabled = "disabled"

	BackendAuto     = "auto"
	BackendNFT      = "nft"
	BackendIptables = "iptables"
	BackendNone     = "none"

	DefaultPolicyDrop   = "drop"
	DefaultPolicyAccept = "accept"

	ActionAccept = "accept"
	ActionDrop   = "drop"

	ChainInput   = "input"
	ChainForward = "forward"
	ChainOutput  = "output"

	ProtoTCP    = "tcp"
	ProtoUDP    = "udp"
	ProtoICMP   = "icmp"
	ProtoICMPv6 = "ipv6-icmp"

	defaultIKEPort  = 500
	defaultNATTPort = 4500
)

// BuildDesiredState generates a backend-agnostic desired firewall state from
// the instance spec and verified policy input. It is pure logic: no I/O, no
// root required. Callers (daemon, dry-run smoke, unit tests) can assert on
// the returned rules without touching the system.
func BuildDesiredState(spec FirewallInstanceSpec, input FirewallPolicyInput) (*FirewallDesiredState, error) {
	if spec.ID == "" {
		return nil, fmt.Errorf("firewall instance spec ID is required")
	}
	if spec.Mode == ModeDisabled {
		return &FirewallDesiredState{Instance: spec}, nil
	}
	prefixes := buildPrefixSets(input)
	desired := &FirewallDesiredState{
		Instance: spec,
		Prefixes: prefixes,
	}
	if spec.IsHost {
		buildHostRules(desired, spec, input)
	} else {
		buildOverlayRules(desired, spec, input)
	}
	return desired, nil
}

// buildPrefixSets partitions prefixes by family and purpose. Revoked prefixes
// (6.3.3 / 6.3.7 deny-first) are filtered out so they never appear in allow
// sets, and are also exposed in RevokedV4/V6 for audit / explicit drop rules.
func buildPrefixSets(input FirewallPolicyInput) PrefixSets {
	revokedSet := buildRevokedSet(input.Revoked)
	var out PrefixSets
	for _, p := range dedupSorted(input.LocalAssigned) {
		if revokedSet[p.String()] {
			continue
		}
		if p.Addr().Is4() {
			out.LocalAssignedV4 = append(out.LocalAssignedV4, p)
		} else {
			out.LocalAssignedV6 = append(out.LocalAssignedV6, p)
		}
	}
	for _, p := range dedupSorted(input.MeshAuthorized) {
		if revokedSet[p.String()] {
			continue
		}
		if p.Addr().Is4() {
			out.MeshAuthorizedV4 = append(out.MeshAuthorizedV4, p)
		} else {
			out.MeshAuthorizedV6 = append(out.MeshAuthorizedV6, p)
		}
	}
	// Audit-only revoked sets.
	for _, p := range dedupSorted(input.Revoked) {
		if p.Addr().Is4() {
			out.RevokedV4 = append(out.RevokedV4, p)
		} else {
			out.RevokedV6 = append(out.RevokedV6, p)
		}
	}
	return out
}

// buildRevokedSet returns a set of revoked prefix strings for fast lookup.
func buildRevokedSet(revoked []netip.Prefix) map[string]bool {
	out := make(map[string]bool, len(revoked))
	for _, p := range revoked {
		out[p.String()] = true
	}
	return out
}

// buildOverlayRules generates input/forward/output chains for an overlay netns.
func buildOverlayRules(desired *FirewallDesiredState, spec FirewallInstanceSpec, input FirewallPolicyInput) {
	prefixes := desired.Prefixes
	defaultPolicy := spec.DefaultPolicy
	if defaultPolicy == "" {
		defaultPolicy = DefaultPolicyDrop
	}
	chainSuffix := chainNameSuffix(spec)

	// --- input chain ---
	ruleIdx := 0
	addRule := func(chain string, r Rule) {
		r.Chain = chain
		if r.ID == "" {
			ruleIdx++
			r.ID = fmt.Sprintf("%s_%s_%d", chainSuffix, chain, ruleIdx)
		}
		switch chain {
		case ChainInput:
			desired.InputRules = append(desired.InputRules, r)
		case ChainForward:
			desired.ForwardRules = append(desired.ForwardRules, r)
		case ChainOutput:
			desired.OutputRules = append(desired.OutputRules, r)
		}
	}

	// 1. loopback accept
	addRule(ChainInput, Rule{Action: ActionAccept, IfaceIn: "lo", Comment: "loopback"})

	// 2. pre_input hook
	if spec.Hooks.PreInput != "" {
		addRule(ChainInput, Rule{Action: "jump", Comment: "pre_input hook", IfaceIn: spec.Hooks.PreInput})
	}

	// 3. BIRD/Babel control traffic (UDP 6696 for babel)
	addRule(ChainInput, Rule{Action: ActionAccept, Proto: ProtoUDP, Port: 6696, Comment: "babel control"})
	// ICMP for health/neighbor discovery
	addRule(ChainInput, Rule{Action: ActionAccept, Proto: ProtoICMP, Comment: "icmp health"})
	addRule(ChainInput, Rule{Action: ActionAccept, Proto: ProtoICMPv6, Comment: "icmpv6 health"})

	// 4. established/related
	addRule(ChainInput, Rule{Action: ActionAccept, Comment: "established related", ID: chainSuffix + "_input_est"})

	// 5. local services
	for _, svc := range spec.LocalServices {
		srcs := svc.Sources
		if len(srcs) == 0 {
			srcs = append(append(srcs, prefixes.MeshAuthorizedV4...), prefixes.MeshAuthorizedV6...)
		}
		addRule(ChainInput, Rule{
			Action:  ActionAccept,
			Proto:   svc.Proto,
			Port:    svc.Port,
			Src:     srcs,
			Comment: fmt.Sprintf("local_service %s/%d", svc.Proto, svc.Port),
		})
	}

	// 6. mesh authorized sources to local assigned prefixes
	if len(prefixes.MeshAuthorizedV4) > 0 || len(prefixes.MeshAuthorizedV6) > 0 {
		allMesh := append(append([]netip.Prefix{}, prefixes.MeshAuthorizedV4...), prefixes.MeshAuthorizedV6...)
		allLocal := append(append([]netip.Prefix{}, prefixes.LocalAssignedV4...), prefixes.LocalAssignedV6...)
		if len(allLocal) > 0 {
			addRule(ChainInput, Rule{
				Action:  ActionAccept,
				Src:     allMesh,
				Dst:     allLocal,
				Comment: "mesh authorized to local assigned",
			})
		}
	}

	// 7. post_input hook
	if spec.Hooks.PostInput != "" {
		addRule(ChainInput, Rule{Action: "jump", Comment: "post_input hook", IfaceIn: spec.Hooks.PostInput})
	}

	// 8. default policy
	addRule(ChainInput, Rule{Action: defaultPolicyVerb(defaultPolicy), Comment: "default policy"})

	// --- forward chain ---
	addRule(ChainForward, Rule{Action: ActionAccept, Comment: "established related", ID: chainSuffix + "_fwd_est"})

	if spec.Hooks.PreForward != "" {
		addRule(ChainForward, Rule{Action: "jump", Comment: "pre_forward hook", IfaceIn: spec.Hooks.PreForward})
	}

	xfrmPat := spec.XFRMTunnelPattern
	if xfrmPat == "" {
		xfrmPat = "hgs*"
	}
	upstreamPats := spec.UpstreamPatterns
	if len(upstreamPats) == 0 {
		upstreamPats = []string{"hgs-upstream*"}
	}

	// XFRM -> XFRM authorized transit (only if forwarding policy allows)
	if input.Forwarding.Transit {
		meshV4 := prefixes.MeshAuthorizedV4
		meshV6 := prefixes.MeshAuthorizedV6
		if transit := filterTransitPrefixes(meshV4, meshV6, input.Forwarding); len(transit) > 0 {
			addRule(ChainForward, Rule{
				Action:   ActionAccept,
				IfaceIn:  xfrmPat,
				IfaceOut: xfrmPat,
				Src:      transit,
				Dst:      transit,
				Comment:  "xfrm transit (transit enabled)",
			})
		}
	} else {
		// Non-transit: explicitly drop XFRM-to-XFRM
		addRule(ChainForward, Rule{
			Action:   ActionDrop,
			IfaceIn:  xfrmPat,
			IfaceOut: xfrmPat,
			Comment:  "non-transit drop",
		})
	}

	// XFRM -> upstream: allow mesh traffic to local assigned prefixes (egress to main network)
	if len(prefixes.LocalAssignedV4) > 0 || len(prefixes.LocalAssignedV6) > 0 {
		localAll := append(append([]netip.Prefix{}, prefixes.LocalAssignedV4...), prefixes.LocalAssignedV6...)
		for _, up := range upstreamPats {
			addRule(ChainForward, Rule{
				Action:   ActionAccept,
				IfaceIn:  xfrmPat,
				IfaceOut: up,
				Dst:      localAll,
				Comment:  "xfrm to upstream local assigned",
			})
		}
	}

	// upstream -> XFRM: allow local/main network to reach mesh authorized prefixes
	if len(prefixes.MeshAuthorizedV4) > 0 || len(prefixes.MeshAuthorizedV6) > 0 {
		meshAll := append(append([]netip.Prefix{}, prefixes.MeshAuthorizedV4...), prefixes.MeshAuthorizedV6...)
		for _, up := range upstreamPats {
			addRule(ChainForward, Rule{
				Action:   ActionAccept,
				IfaceIn:  up,
				IfaceOut: xfrmPat,
				Dst:      meshAll,
				Comment:  "upstream to xfrm mesh authorized",
			})
		}
	}

	if spec.Hooks.PostForward != "" {
		addRule(ChainForward, Rule{Action: "jump", Comment: "post_forward hook", IfaceIn: spec.Hooks.PostForward})
	}
	addRule(ChainForward, Rule{Action: defaultPolicyVerb(defaultPolicy), Comment: "default policy"})

	// --- output chain ---
	addRule(ChainOutput, Rule{Action: ActionAccept, IfaceOut: "lo", Comment: "loopback"})
	addRule(ChainOutput, Rule{Action: ActionAccept, Proto: ProtoUDP, Port: 6696, Comment: "babel control"})
	addRule(ChainOutput, Rule{Action: ActionAccept, Proto: ProtoICMP, Comment: "icmp health"})
	addRule(ChainOutput, Rule{Action: ActionAccept, Proto: ProtoICMPv6, Comment: "icmpv6 health"})

	if len(prefixes.LocalAssignedV4) > 0 || len(prefixes.LocalAssignedV6) > 0 {
		localAll := append(append([]netip.Prefix{}, prefixes.LocalAssignedV4...), prefixes.LocalAssignedV6...)
		addRule(ChainOutput, Rule{Action: ActionAccept, Src: localAll, Comment: "local assigned source"})
	}
	if spec.Hooks.PostOutput != "" {
		addRule(ChainOutput, Rule{Action: "jump", Comment: "post_output hook", IfaceOut: spec.Hooks.PostOutput})
	}
	// Output default to accept for overlay services; can be tightened.
	addRule(ChainOutput, Rule{Action: ActionAccept, Comment: "default policy"})
}

// buildHostRules generates host-side IKE/NAT-T ingress and optional redirect grace.
func buildHostRules(desired *FirewallDesiredState, spec FirewallInstanceSpec, input FirewallPolicyInput) {
	ikePort := spec.CharonIKEPort
	if ikePort == 0 {
		ikePort = defaultIKEPort
	}
	nattPort := spec.CharonNATTPort
	if nattPort == 0 {
		nattPort = defaultNATTPort
	}

	// IKE ingress
	if spec.HostPorts.IKE {
		desired.HostIngress = append(desired.HostIngress, buildHostIngress(ProtoUDP, ikePort, spec.ListenAddrs, "ike ingress"))
	}
	// NAT-T ingress
	if spec.HostPorts.NATT {
		desired.HostIngress = append(desired.HostIngress, buildHostIngress(ProtoUDP, nattPort, spec.ListenAddrs, "natt ingress"))
	}
	// WireGuard ingress (for Phase 7 WireGuard transport driver).
	wgPort := spec.WGPort
	if wgPort == 0 {
		wgPort = 51820
	}
	if spec.HostPorts.WG {
		desired.HostIngress = append(desired.HostIngress, buildHostIngress(ProtoUDP, wgPort, spec.ListenAddrs, "wg ingress"))
	}

	// Redirect advertised ports to the current local listener ports. Current
	// advertised ports make port_range usable when charon keeps stable 500/4500
	// sockets; previous ports keep rotate grace alive during the configured
	// window. The daemon feeds concrete current/previous ports from the local
	// signed ipsec/ports record.
	if spec.RedirectGrace.Enabled {
		addNatRedirects(desired, input.AdvertisedCurrentIKEPorts, ikePort, "redirect current", "ike", spec.ListenAddrs)
		addNatRedirects(desired, input.AdvertisedPreviousIKEPorts, ikePort, "redirect grace", "ike", spec.ListenAddrs)
		addNatRedirects(desired, input.AdvertisedCurrentNATTPorts, nattPort, "redirect current", "natt", spec.ListenAddrs)
		addNatRedirects(desired, input.AdvertisedPreviousNATTPorts, nattPort, "redirect grace", "natt", spec.ListenAddrs)
		// WireGuard redirect: old advertised WG ports → current WG port.
		// Reserved for Phase 7 WireGuard port rotation.
		for _, prev := range input.AdvertisedPreviousWGPorts {
			if prev == wgPort || prev == 0 {
				continue
			}
			desired.NatRedirects = append(desired.NatRedirects, NatRedirectRule{
				Proto:       ProtoUDP,
				OriginalDst: prev,
				RedirectTo:  wgPort,
				DstAddr:     firstListenAddr(spec.ListenAddrs),
				Comment:     fmt.Sprintf("redirect grace %d -> %d (wg)", prev, wgPort),
			})
		}
	}

	// Note: No SNAT (MASQUERADE) is needed for outbound transport traffic.
	// StrongSwan/WireGuard initiate outbound connections from ephemeral local
	// source ports; the remote peer sees the actual source IP/port and does
	// not need it translated. DNAT/redirect only applies to inbound traffic
	// hitting advertised entry ports.
}

// addNatRedirects creates DNAT redirect rules for port rotation.
// It creates rules without specific DstAddr, so they match all addresses on
// all interfaces. This supports IPv6 interfaces with multiple addresses,
// as the redirect rule will apply to all of them without needing a per-address rule.
func addNatRedirects(desired *FirewallDesiredState, ports []uint16, target uint16, reason, label string, listenAddrs []netip.Addr) {
	seen := make(map[uint16]bool, len(desired.NatRedirects)+len(ports))
	for _, existing := range desired.NatRedirects {
		if existing.RedirectTo == target {
			seen[existing.OriginalDst] = true
		}
	}
	for _, port := range ports {
		if port == 0 || port == target || seen[port] {
			continue
		}
		seen[port] = true
		// Leave DstAddr empty to match all addresses on all interfaces.
		// This supports IPv6 multi-address scenarios and works for both IPv4 and IPv6
		// in nftables inet tables. The redirect only changes the port, not the address.
		desired.NatRedirects = append(desired.NatRedirects, NatRedirectRule{
			Proto:       ProtoUDP,
			OriginalDst: port,
			RedirectTo:  target,
			DstAddr:     netip.Addr{}, // Empty to match all addresses
			Comment:     fmt.Sprintf("%s %d -> %d (%s)", reason, port, target, label),
		})
	}
}

func buildHostIngress(proto string, port uint16, listenAddrs []netip.Addr, comment string) HostIngressRule {
	rule := HostIngressRule{Proto: proto, Port: port, Comment: comment}
	if len(listenAddrs) == 1 {
		rule.DstAddr = listenAddrs[0]
	}
	return rule
}

func firstListenAddr(addrs []netip.Addr) netip.Addr {
	if len(addrs) == 0 {
		return netip.Addr{}
	}
	return addrs[0]
}

// filterTransitPrefixes applies allow/deny prefix lists from the forwarding policy.
func filterTransitPrefixes(v4, v6 []netip.Prefix, policy ForwardingPolicy) []netip.Prefix {
	all := append(append([]netip.Prefix{}, v4...), v6...)
	if len(policy.AllowPrefixes) > 0 {
		allowed := make(map[string]bool)
		for _, p := range policy.AllowPrefixes {
			allowed[p.String()] = true
		}
		var filtered []netip.Prefix
		for _, p := range all {
			if allowed[p.String()] {
				filtered = append(filtered, p)
			}
		}
		all = filtered
	}
	if len(policy.DenyPrefixes) > 0 {
		denied := make(map[string]bool)
		for _, p := range policy.DenyPrefixes {
			denied[p.String()] = true
		}
		var filtered []netip.Prefix
		for _, p := range all {
			if !denied[p.String()] {
				filtered = append(filtered, p)
			}
		}
		all = filtered
	}
	return all
}

func defaultPolicyVerb(policy string) string {
	if policy == DefaultPolicyAccept {
		return ActionAccept
	}
	return ActionDrop
}

func chainNameSuffix(spec FirewallInstanceSpec) string {
	prefix := spec.OwnerPrefix
	if prefix == "" {
		prefix = "higgs"
	}
	if spec.IsHost {
		return prefix + "_host"
	}
	return prefix + "_" + spec.NetNS
}

func dedupSorted(prefixes []netip.Prefix) []netip.Prefix {
	seen := make(map[string]bool)
	var out []netip.Prefix
	for _, p := range prefixes {
		key := p.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].String() < out[j].String()
	})
	return out
}

// DesiredStateHash returns a stable hash of the desired state for generation
// tracking and change detection.
func DesiredStateHash(desired *FirewallDesiredState) string {
	if desired == nil {
		return ""
	}
	h := sha256.New()
	fmt.Fprintln(h, desired.Instance.ID)
	fmt.Fprintln(h, desired.Instance.Mode)
	fmt.Fprintln(h, desired.Instance.DefaultPolicy)
	for _, p := range desired.Prefixes.LocalAssignedV4 {
		fmt.Fprintln(h, "lav4", p.String())
	}
	for _, p := range desired.Prefixes.LocalAssignedV6 {
		fmt.Fprintln(h, "lav6", p.String())
	}
	for _, p := range desired.Prefixes.MeshAuthorizedV4 {
		fmt.Fprintln(h, "mav4", p.String())
	}
	for _, p := range desired.Prefixes.MeshAuthorizedV6 {
		fmt.Fprintln(h, "mav6", p.String())
	}
	for _, p := range desired.Prefixes.RevokedV4 {
		fmt.Fprintln(h, "rev4", p.String())
	}
	for _, p := range desired.Prefixes.RevokedV6 {
		fmt.Fprintln(h, "rev6", p.String())
	}
	for _, r := range desired.InputRules {
		fmt.Fprintln(h, "in", r.Action, r.Proto, r.Port, r.IfaceIn, r.IfaceOut, r.Comment)
	}
	for _, r := range desired.ForwardRules {
		fmt.Fprintln(h, "fwd", r.Action, r.Proto, r.Port, r.IfaceIn, r.IfaceOut, r.Comment)
	}
	for _, r := range desired.OutputRules {
		fmt.Fprintln(h, "out", r.Action, r.Proto, r.Port, r.IfaceIn, r.IfaceOut, r.Comment)
	}
	for _, r := range desired.HostIngress {
		fmt.Fprintln(h, "hi", r.Proto, r.Port, r.DstAddr.String(), r.Comment)
	}
	for _, r := range desired.NatRedirects {
		fmt.Fprintln(h, "nat", r.Proto, r.OriginalDst, r.RedirectTo, r.DstAddr.String(), r.Comment)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// OwnerToken derives a stable owner token for an instance.
func OwnerToken(spec FirewallInstanceSpec) string {
	prefix := spec.OwnerPrefix
	if prefix == "" {
		prefix = "higgs"
	}
	target := spec.NetNS
	if spec.IsHost {
		target = "host"
	}
	h := sha256.Sum256([]byte(prefix + "/" + target + "/" + spec.ID))
	return hex.EncodeToString(h[:])[:12]
}

// DesiredObjects returns the set of owned object references for a desired state.
// Used by Plan to compute the create/delete diff against observed state.
func DesiredObjects(desired *FirewallDesiredState) []FirewallObjectRef {
	if desired == nil || desired.Instance.Mode == ModeDisabled {
		return nil
	}
	prefix := desired.Instance.OwnerPrefix
	if prefix == "" {
		prefix = "higgs"
	}
	target := desired.Instance.NetNS
	if desired.Instance.IsHost {
		target = "host"
	}
	tableName := prefix + "_" + target
	var refs []FirewallObjectRef
	refs = append(refs, FirewallObjectRef{Kind: "table", Family: "inet", Name: tableName})
	refs = append(refs, FirewallObjectRef{Kind: "chain", Family: "inet", Name: tableName + "_input"})
	refs = append(refs, FirewallObjectRef{Kind: "chain", Family: "inet", Name: tableName + "_forward"})
	refs = append(refs, FirewallObjectRef{Kind: "chain", Family: "inet", Name: tableName + "_output"})
	if len(desired.Prefixes.MeshAuthorizedV4) > 0 {
		refs = append(refs, FirewallObjectRef{Kind: "set", Family: "inet", Name: tableName + "_mesh_v4"})
	}
	if len(desired.Prefixes.MeshAuthorizedV6) > 0 {
		refs = append(refs, FirewallObjectRef{Kind: "set", Family: "inet", Name: tableName + "_mesh_v6"})
	}
	if desired.Instance.IsHost {
		if len(desired.HostIngress) > 0 {
			refs = append(refs, FirewallObjectRef{Kind: "chain", Family: "inet", Name: tableName + "_input"})
		}
		if len(desired.NatRedirects) > 0 {
			refs = append(refs, FirewallObjectRef{Kind: "nat_redirect", Family: "inet", Name: tableName + "_prerouting"})
		}
	}
	return refs
}

// Ensure unused import doesn't break build when strings is only used conditionally.
var _ = strings.TrimSpace
