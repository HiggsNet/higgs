package bird

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// VethManager manages veth pairs for upstream connectivity.
type VethManager interface {
	// EnsureVethPair creates the veth pair if it doesn't exist and configures
	// addresses on the mesh side. It is idempotent.
	EnsureVethPair(ctx context.Context, spec VethSpec) error

	// DeleteVethPair removes the veth pair. It is idempotent.
	DeleteVethPair(ctx context.Context, spec VethSpec) error
}

// VethSpec describes a veth pair connecting mesh netns to the main network.
type VethSpec struct {
	// MeshInterface is the veth endpoint name inside the mesh netns.
	MeshInterface string

	// PeerInterface is the veth endpoint name in the main/peer netns.
	PeerInterface string

	// MeshNetns is the named netns where the mesh endpoint lives.
	MeshNetns string

	// PeerNetns is the named netns for the peer endpoint. Empty = init netns.
	PeerNetns string

	// MeshIPv4LL is the optional IPv4 CIDR for the mesh endpoint.
	MeshIPv4LL string

	// MeshIPv6LL is the optional IPv6 CIDR for the mesh endpoint.
	MeshIPv6LL string

	// PeerIPv4LL is the optional IPv4 CIDR for the peer endpoint.
	PeerIPv4LL string

	// PeerIPv6LL is the optional IPv6 CIDR for the peer endpoint.
	PeerIPv6LL string
}

// ExecVethManager implements VethManager using the `ip` command.
type ExecVethManager struct {
	runner func(ctx context.Context, cmd string, args ...string) *exec.Cmd
}

// NewExecVethManager returns a VethManager that uses `ip` directly.
func NewExecVethManager() *ExecVethManager {
	return &ExecVethManager{
		runner: exec.CommandContext,
	}
}

var _ VethManager = (*ExecVethManager)(nil)

// EnsureVethPair creates the veth pair and configures addresses.
func (m *ExecVethManager) EnsureVethPair(ctx context.Context, spec VethSpec) error {
	if spec.MeshInterface == "" || spec.PeerInterface == "" {
		return fmt.Errorf("veth: mesh and peer interface names are required")
	}

	if !m.ifaceExistsInNetns(ctx, spec.MeshNetns, spec.MeshInterface) {
		// Create the veth pair in the mesh netns, then move the peer to the
		// target netns. We create both endpoints in the mesh netns first, then
		// move the peer end.
		args := []string{"netns", "exec", spec.MeshNetns, "ip", "link", "add", spec.MeshInterface, "type", "veth", "peer", "name", spec.PeerInterface}
		cmd := m.runner(ctx, "ip", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			// If the pair already exists (race), continue.
			if !strings.Contains(string(out), "exists") {
				return fmt.Errorf("create veth pair: %w (%s)", err, strings.TrimSpace(string(out)))
			}
		}

		// Bring up the mesh side.
		if err := m.runInNetns(ctx, spec.MeshNetns, "ip", "link", "set", spec.MeshInterface, "up"); err != nil {
			return fmt.Errorf("set mesh veth up: %w", err)
		}

		// Move peer to the target netns (if different from mesh netns).
		if spec.PeerNetns == "" {
			// Move to init netns: use PID 1 or just set netns to 1.
			// Actually, from inside a named netns, moving peer to init netns
			// requires: ip link set <peer> netns 1
			if err := m.runInNetns(ctx, spec.MeshNetns, "ip", "link", "set", spec.PeerInterface, "netns", "1"); err != nil {
				return fmt.Errorf("move peer to init netns: %w", err)
			}
			// Bring up peer in init netns.
			if err := m.run(ctx, "ip", "link", "set", spec.PeerInterface, "up"); err != nil {
				return fmt.Errorf("set peer veth up: %w", err)
			}
		} else if spec.PeerNetns != spec.MeshNetns {
			if err := m.runInNetns(ctx, spec.MeshNetns, "ip", "link", "set", spec.PeerInterface, "netns", spec.PeerNetns); err != nil {
				return fmt.Errorf("move peer to netns %s: %w", spec.PeerNetns, err)
			}
			if err := m.runInNetns(ctx, spec.PeerNetns, "ip", "link", "set", spec.PeerInterface, "up"); err != nil {
				return fmt.Errorf("set peer veth up: %w", err)
			}
		} else {
			// Both endpoints in same netns: just bring up the peer.
			if err := m.runInNetns(ctx, spec.MeshNetns, "ip", "link", "set", spec.PeerInterface, "up"); err != nil {
				return fmt.Errorf("set peer veth up: %w", err)
			}
		}
	}

	if err := m.ensureAddresses(ctx, spec); err != nil {
		return err
	}
	if err := m.enableInterfaceForwarding(ctx, spec.MeshNetns, spec.MeshInterface); err != nil {
		return err
	}
	if spec.PeerNetns != "" && spec.PeerNetns != spec.MeshNetns {
		if err := m.enableInterfaceForwarding(ctx, spec.PeerNetns, spec.PeerInterface); err != nil {
			return err
		}
	} else if spec.PeerNetns == "" {
		if err := m.enableInterfaceForwarding(ctx, "", spec.PeerInterface); err != nil {
			return err
		}
	}
	return nil
}

// DeleteVethPair removes the veth pair. Deleting one end removes both.
func (m *ExecVethManager) DeleteVethPair(ctx context.Context, spec VethSpec) error {
	// Try deleting from the mesh netns first.
	if m.ifaceExistsInNetns(ctx, spec.MeshNetns, spec.MeshInterface) {
		if err := m.runInNetns(ctx, spec.MeshNetns, "ip", "link", "delete", spec.MeshInterface); err != nil {
			return fmt.Errorf("delete veth %s: %w", spec.MeshInterface, err)
		}
		return nil
	}
	// Try deleting from the peer netns.
	if spec.PeerNetns != "" && spec.PeerNetns != spec.MeshNetns {
		if m.ifaceExistsInNetns(ctx, spec.PeerNetns, spec.PeerInterface) {
			if err := m.runInNetns(ctx, spec.PeerNetns, "ip", "link", "delete", spec.PeerInterface); err != nil {
				return fmt.Errorf("delete veth %s: %w", spec.PeerInterface, err)
			}
		}
	} else if spec.PeerNetns == "" {
		// Peer is in init netns.
		if m.ifaceExists(ctx, spec.PeerInterface) {
			if err := m.run(ctx, "ip", "link", "delete", spec.PeerInterface); err != nil {
				return fmt.Errorf("delete veth %s: %w", spec.PeerInterface, err)
			}
		}
	}
	return nil
}

func (m *ExecVethManager) ensureAddresses(ctx context.Context, spec VethSpec) error {
	if spec.MeshIPv4LL != "" {
		existing, err := m.getAddrInNetns(ctx, spec.MeshNetns, spec.MeshInterface)
		if err == nil && !strings.Contains(existing, spec.MeshIPv4LL) {
			if err := m.runInNetns(ctx, spec.MeshNetns, "ip", "addr", "replace", spec.MeshIPv4LL, "dev", spec.MeshInterface); err != nil {
				return fmt.Errorf("set mesh ipv4: %w", err)
			}
		}
	}
	if spec.MeshIPv6LL != "" {
		existing, err := m.getAddrInNetns(ctx, spec.MeshNetns, spec.MeshInterface)
		if err == nil && !strings.Contains(existing, spec.MeshIPv6LL) {
			if err := m.runInNetns(ctx, spec.MeshNetns, "ip", "addr", "replace", spec.MeshIPv6LL, "dev", spec.MeshInterface); err != nil {
				return fmt.Errorf("set mesh ipv6: %w", err)
			}
		}
	}
	if spec.PeerIPv4LL != "" {
		if err := m.ensurePeerAddress(ctx, spec, spec.PeerIPv4LL, "ipv4"); err != nil {
			return err
		}
	}
	if spec.PeerIPv6LL != "" {
		if err := m.ensurePeerAddress(ctx, spec, spec.PeerIPv6LL, "ipv6"); err != nil {
			return err
		}
	}
	return nil
}

func (m *ExecVethManager) ensurePeerAddress(ctx context.Context, spec VethSpec, cidr, family string) error {
	if spec.PeerNetns == "" {
		existing, err := m.getAddr(ctx, spec.PeerInterface)
		if err == nil && !strings.Contains(existing, cidr) {
			if err := m.run(ctx, "ip", "addr", "replace", cidr, "dev", spec.PeerInterface); err != nil {
				return fmt.Errorf("set peer %s: %w", family, err)
			}
		}
		return nil
	}
	existing, err := m.getAddrInNetns(ctx, spec.PeerNetns, spec.PeerInterface)
	if err == nil && !strings.Contains(existing, cidr) {
		if err := m.runInNetns(ctx, spec.PeerNetns, "ip", "addr", "replace", cidr, "dev", spec.PeerInterface); err != nil {
			return fmt.Errorf("set peer %s: %w", family, err)
		}
	}
	return nil
}

func (m *ExecVethManager) ifaceExistsInNetns(ctx context.Context, netns, iface string) bool {
	cmd := m.runner(ctx, "ip", "netns", "exec", netns, "ip", "link", "show", iface)
	return cmd.Run() == nil
}

func (m *ExecVethManager) ifaceExists(ctx context.Context, iface string) bool {
	cmd := m.runner(ctx, "ip", "link", "show", iface)
	return cmd.Run() == nil
}

func (m *ExecVethManager) getAddrInNetns(ctx context.Context, netns, iface string) (string, error) {
	cmd := m.runner(ctx, "ip", "netns", "exec", netns, "ip", "addr", "show", iface)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (m *ExecVethManager) getAddr(ctx context.Context, iface string) (string, error) {
	cmd := m.runner(ctx, "ip", "addr", "show", iface)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (m *ExecVethManager) runInNetns(ctx context.Context, netns string, cmd string, args ...string) error {
	if netns == "" || netns == "host" {
		return m.run(ctx, cmd, args...)
	}
	full := append([]string{"netns", "exec", netns, cmd}, args...)
	return m.run(ctx, "ip", full...)
}

func (m *ExecVethManager) enableInterfaceForwarding(ctx context.Context, netns, iface string) error {
	params := []string{
		fmt.Sprintf("net.ipv4.conf.%s.forwarding=1", iface),
		fmt.Sprintf("net.ipv6.conf.%s.forwarding=1", iface),
	}
	for _, p := range params {
		if err := m.sysctl(ctx, netns, "-w", p); err != nil {
			return err
		}
	}
	return nil
}

func (m *ExecVethManager) sysctl(ctx context.Context, netns string, args ...string) error {
	if netns == "" || netns == "host" {
		return m.run(ctx, "sysctl", args...)
	}
	full := append([]string{"netns", "exec", netns, "sysctl"}, args...)
	return m.run(ctx, "ip", full...)
}

func (m *ExecVethManager) run(ctx context.Context, cmd string, args ...string) error {
	c := m.runner(ctx, cmd, args...)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", cmd, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
