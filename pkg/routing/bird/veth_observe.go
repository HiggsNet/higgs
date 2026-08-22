package bird

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

type vethEndpointState struct {
	exists          bool
	up              bool
	addrGenDisabled bool
	forwarding4     bool
	forwarding6     bool
	addresses       map[netip.Prefix]struct{}
}

type vethAddrJSON struct {
	IfName   string             `json:"ifname"`
	Flags    []string           `json:"flags"`
	AddrInfo []vethAddrInfoJSON `json:"addr_info"`
}

type vethAddrInfoJSON struct {
	Local     string `json:"local"`
	PrefixLen int    `json:"prefixlen"`
}

func (m *ExecVethManager) ensureObservedVethPair(ctx context.Context, spec VethSpec) (bool, error) {
	if spec.MeshInterface == "" || spec.PeerInterface == "" {
		return true, fmt.Errorf("veth: mesh and peer interface names are required")
	}
	mesh, err := m.observeVethEndpoint(ctx, spec.MeshNetns, spec.MeshInterface)
	if err != nil || !mesh.exists {
		return false, nil
	}
	peer, err := m.observeVethEndpoint(ctx, spec.PeerNetns, spec.PeerInterface)
	if err != nil || !peer.exists {
		return false, nil
	}

	if err := m.repairVethEndpoint(ctx, spec.MeshNetns, spec.MeshInterface, mesh); err != nil {
		return true, err
	}
	if err := m.repairVethEndpoint(ctx, spec.PeerNetns, spec.PeerInterface, peer); err != nil {
		return true, err
	}
	for _, desired := range []struct {
		netns string
		iface string
		cidr  string
		state vethEndpointState
		label string
	}{
		{spec.MeshNetns, spec.MeshInterface, spec.MeshIPv4LL, mesh, "mesh ipv4"},
		{spec.MeshNetns, spec.MeshInterface, spec.MeshIPv6LL, mesh, "mesh ipv6"},
		{spec.PeerNetns, spec.PeerInterface, spec.PeerIPv4LL, peer, "peer ipv4"},
		{spec.PeerNetns, spec.PeerInterface, spec.PeerIPv6LL, peer, "peer ipv6"},
	} {
		if desired.cidr == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(desired.cidr)
		if err != nil {
			return true, fmt.Errorf("invalid %s address %q: %w", desired.label, desired.cidr, err)
		}
		if _, ok := desired.state.addresses[prefix]; ok {
			continue
		}
		if err := m.runInNetns(ctx, desired.netns, m.ipCommand(), "addr", "replace", prefix.String(), "dev", desired.iface); err != nil {
			return true, fmt.Errorf("set %s: %w", desired.label, err)
		}
	}
	return true, nil
}

func (m *ExecVethManager) observeVethEndpoint(ctx context.Context, netns, iface string) (vethEndpointState, error) {
	state := vethEndpointState{addresses: make(map[netip.Prefix]struct{})}
	out, err := m.outputInNetns(ctx, netns, m.ipCommand(), "-j", "addr", "show", "dev", iface)
	if err != nil {
		return state, err
	}
	var rows []vethAddrJSON
	if err := json.Unmarshal(out, &rows); err != nil {
		return state, fmt.Errorf("parse veth address JSON for %s: %w", iface, err)
	}
	if len(rows) != 1 || rows[0].IfName != iface {
		return state, fmt.Errorf("veth address JSON for %s returned %d mismatched rows", iface, len(rows))
	}
	state.exists = true
	for _, flag := range rows[0].Flags {
		if strings.EqualFold(flag, "UP") {
			state.up = true
		}
	}
	for _, info := range rows[0].AddrInfo {
		addr, err := netip.ParseAddr(info.Local)
		if err != nil || info.PrefixLen < 0 || info.PrefixLen > addr.BitLen() {
			continue
		}
		state.addresses[netip.PrefixFrom(addr, info.PrefixLen)] = struct{}{}
	}

	sysctlOut, err := m.outputSysctlInNetns(ctx, netns,
		"-n",
		fmt.Sprintf("net.ipv6.conf.%s.addr_gen_mode", iface),
		fmt.Sprintf("net.ipv4.conf.%s.forwarding", iface),
		fmt.Sprintf("net.ipv6.conf.%s.forwarding", iface),
	)
	if err != nil {
		return state, err
	}
	values := strings.Fields(string(sysctlOut))
	if len(values) != 3 {
		return state, fmt.Errorf("inspect veth sysctl for %s: got %d values, want 3", iface, len(values))
	}
	state.addrGenDisabled = values[0] == "1"
	state.forwarding4 = values[1] == "1"
	state.forwarding6 = values[2] == "1"
	return state, nil
}

func (m *ExecVethManager) repairVethEndpoint(ctx context.Context, netns, iface string, state vethEndpointState) error {
	if !state.addrGenDisabled {
		if err := m.runInNetns(ctx, netns, m.ipCommand(), "link", "set", iface, "addrgenmode", "none"); err != nil {
			return fmt.Errorf("disable auto link-local on %s: %w", iface, err)
		}
	}
	if !state.up {
		if err := m.runInNetns(ctx, netns, m.ipCommand(), "link", "set", iface, "up"); err != nil {
			return fmt.Errorf("set veth %s up: %w", iface, err)
		}
	}
	if !state.forwarding4 {
		if err := m.sysctl(ctx, netns, "-w", fmt.Sprintf("net.ipv4.conf.%s.forwarding=1", iface)); err != nil {
			return err
		}
	}
	if !state.forwarding6 {
		if err := m.sysctl(ctx, netns, "-w", fmt.Sprintf("net.ipv6.conf.%s.forwarding=1", iface)); err != nil {
			return err
		}
	}
	return nil
}

func (m *ExecVethManager) outputInNetns(ctx context.Context, netns, command string, args ...string) ([]byte, error) {
	if netns == "" || netns == "host" {
		return m.runner(ctx, command, args...).CombinedOutput()
	}
	full := append([]string{"netns", "exec", netns, command}, args...)
	return m.runner(ctx, m.ipCommand(), full...).CombinedOutput()
}

func (m *ExecVethManager) outputSysctlInNetns(ctx context.Context, netns string, args ...string) ([]byte, error) {
	return m.outputInNetns(ctx, netns, m.sysctlCommand(), args...)
}

func resolveVethExecutable(name string) string {
	path, err := exec.LookPath(name)
	if err != nil {
		return name
	}
	return path
}

func (m *ExecVethManager) ipCommand() string {
	if m.ipPath != "" {
		return m.ipPath
	}
	return "ip"
}

func (m *ExecVethManager) sysctlCommand() string {
	if m.sysctlPath != "" {
		return m.sysctlPath
	}
	return "sysctl"
}
