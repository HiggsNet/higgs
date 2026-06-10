package ipsec

import (
	"fmt"
	"net/netip"
	"sort"
)

const (
	StrongSwanIKEVersion = "2"
	StrongSwanAuthPubkey = "pubkey"
	StrongSwanChildMode  = "tunnel"
)

func BuildLoadConnMessage(spec TransportLinkSpec) (map[string]any, error) {
	if spec.TransportID == "" {
		return nil, fmt.Errorf("transport id is required")
	}
	if spec.LocalZone == "" {
		return nil, fmt.Errorf("local zone is required")
	}
	if spec.PeerZone == "" {
		return nil, fmt.Errorf("peer zone is required")
	}
	if spec.XFRMIfID == 0 {
		return nil, fmt.Errorf("xfrm if_id is required")
	}
	conn, err := BuildStrongSwanConnection(spec)
	if err != nil {
		return nil, err
	}
	return map[string]any{spec.TransportID: conn}, nil
}

func BuildStrongSwanConnection(spec TransportLinkSpec) (map[string]any, error) {
	point, hasPoint := firstContactPoint(spec.ContactPoints)
	if !hasPoint && spec.Direction != DirectionInbound {
		return nil, fmt.Errorf("at least one contact point is required")
	}
	remoteAddr, err := strongSwanRemoteAddress(point, hasPoint)
	if err != nil {
		return nil, err
	}
	childName := ChildSAName(spec)
	conn := map[string]any{
		"version":      StrongSwanIKEVersion,
		"remote_addrs": []string{remoteAddr},
		"encap":        "yes",
		"local": map[string]any{
			"auth": StrongSwanAuthPubkey,
			"id":   string(spec.LocalZone),
		},
		"remote": map[string]any{
			"auth": StrongSwanAuthPubkey,
			"id":   remoteIdentity(spec),
		},
		"children": map[string]any{
			childName: routeBasedChildSA(spec),
		},
	}
	if hasPoint {
		conn["remote_port"] = fmt.Sprintf("%d", chooseIKEPort(point))
	}
	return conn, nil
}

func ChildSAName(spec TransportLinkSpec) string {
	if spec.TransportID == "" {
		return "higgs-child"
	}
	return spec.TransportID + "-child"
}

func routeBasedChildSA(spec TransportLinkSpec) map[string]any {
	return map[string]any{
		"mode":      StrongSwanChildMode,
		"local_ts":  broadTrafficSelectors(spec.LocalTunnelAddr),
		"remote_ts": broadTrafficSelectors(spec.PeerTunnelAddr),
		"if_id_in":  fmt.Sprintf("%d", spec.XFRMIfID),
		"if_id_out": fmt.Sprintf("%d", spec.XFRMIfID),
	}
}

func broadTrafficSelectors(addr netip.Addr) []string {
	if addr.IsValid() && addr.Is4() {
		return []string{"0.0.0.0/0"}
	}
	if addr.IsValid() && addr.Is6() {
		return []string{"::/0"}
	}
	return []string{"0.0.0.0/0", "::/0"}
}

func firstContactPoint(points []ContactPoint) (ContactPoint, bool) {
	if len(points) == 0 {
		return ContactPoint{}, false
	}
	copied := append([]ContactPoint(nil), points...)
	sort.SliceStable(copied, func(i, j int) bool {
		if copied[i].Current != copied[j].Current {
			return copied[i].Current
		}
		if copied[i].Priority != copied[j].Priority {
			return copied[i].Priority > copied[j].Priority
		}
		if copied[i].Generation != copied[j].Generation {
			return copied[i].Generation > copied[j].Generation
		}
		return copied[i].Address < copied[j].Address
	})
	return copied[0], true
}

func strongSwanRemoteAddress(point ContactPoint, hasPoint bool) (string, error) {
	if !hasPoint {
		return "%any", nil
	}
	remoteAddr := point.Address
	if remoteAddr == "" {
		remoteAddr = point.Host
	}
	if remoteAddr == "" {
		return "", fmt.Errorf("contact point address or host is required")
	}
	return remoteAddr, nil
}

func chooseIKEPort(point ContactPoint) uint16 {
	if point.IKEPort != 0 {
		return point.IKEPort
	}
	if point.NATTPort != 0 {
		return point.NATTPort
	}
	return DefaultIKEPort
}

func remoteIdentity(spec TransportLinkSpec) string {
	if spec.IKEIdentity != "" {
		return spec.IKEIdentity
	}
	return string(spec.PeerZone)
}

func parseSAStates(event map[string]any) []SAState {
	var states []SAState
	for name, raw := range event {
		body, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		state := SAState{Name: name}
		if peer, ok := body["remote-host"].(string); ok {
			state.Peer = peer
		}
		if endpoint, ok := body["remote-port"].(string); ok {
			state.Endpoint = endpoint
		}
		children, _ := body["child-sas"].(map[string]any)
		for childName, childRaw := range children {
			child, _ := childRaw.(map[string]any)
			childState := state
			childState.ChildSA = childName
			if ifID, ok := child["if-id-out"].(string); ok {
				var parsed uint32
				_, _ = fmt.Sscanf(ifID, "%d", &parsed)
				childState.XFRMIfID = parsed
			}
			childState.Established = true
			states = append(states, childState)
		}
		if len(children) == 0 {
			state.Established = true
			states = append(states, state)
		}
	}
	return states
}
