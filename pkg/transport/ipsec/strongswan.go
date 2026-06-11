package ipsec

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
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
	return points[0], true
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
		remoteHost := stringValue(body["remote-host"])
		remotePort := stringValue(body["remote-port"])
		localHost := stringValue(body["local-host"])
		localPort := stringValue(body["local-port"])
		state.Peer = remoteHost
		state.LocalIdentity = stringValue(body["local-id"])
		state.RemoteIdentity = stringValue(body["remote-id"])
		state.LocalEndpoint = joinEndpoint(localHost, localPort)
		state.RemoteEndpoint = joinEndpoint(remoteHost, remotePort)
		state.Endpoint = state.RemoteEndpoint
		children, _ := body["child-sas"].(map[string]any)
		for childName, childRaw := range children {
			child, _ := childRaw.(map[string]any)
			childState := state
			childState.ChildSA = childName
			childState.XFRMIfID = firstUint32(child["if-id-out"], child["if-id-in"])
			childState.ReqID = uint32Value(child["reqid"])
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

func stringValue(v any) string {
	switch value := v.(type) {
	case string:
		return value
	case []byte:
		return string(value)
	case fmt.Stringer:
		return value.String()
	default:
		return ""
	}
}

func uint32Value(v any) uint32 {
	switch value := v.(type) {
	case uint32:
		return value
	case uint64:
		return uint32(value)
	case uint:
		return uint32(value)
	case int:
		if value > 0 {
			return uint32(value)
		}
	case int64:
		if value > 0 {
			return uint32(value)
		}
	case float64:
		if value > 0 {
			return uint32(value)
		}
	case string:
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err == nil {
			return uint32(parsed)
		}
	case []byte:
		parsed, err := strconv.ParseUint(string(value), 10, 32)
		if err == nil {
			return uint32(parsed)
		}
	}
	return 0
}

func firstUint32(values ...any) uint32 {
	for _, value := range values {
		if parsed := uint32Value(value); parsed != 0 {
			return parsed
		}
	}
	return 0
}

func joinEndpoint(host, port string) string {
	if host == "" {
		return ""
	}
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}
