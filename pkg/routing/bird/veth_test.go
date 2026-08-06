package bird

import (
	"context"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

type vethRecordedCommand struct {
	name string
	args []string
}

func TestExecVethManagerSetsForwardingOnNewVethPair(t *testing.T) {
	var commands []vethRecordedCommand
	m := &ExecVethManager{
		runner: func(_ context.Context, name string, args ...string) *exec.Cmd {
			commands = append(commands, vethRecordedCommand{name: name, args: append([]string(nil), args...)})
			if name == "ip" && strings.Contains(strings.Join(args, " "), "link show") {
				return exec.Command("false")
			}
			return exec.Command("true")
		},
	}

	spec := VethSpec{
		MeshInterface: "phvmesh",
		PeerInterface: "phvpeer",
		MeshNetns:     "mesh-ns",
		PeerNetns:     "",
		MeshIPv4LL:    "169.254.1.1/30",
		PeerIPv4LL:    "169.254.1.2/30",
	}
	if err := m.EnsureVethPair(context.Background(), spec); err != nil {
		t.Fatalf("EnsureVethPair: %v", err)
	}

	got := vethCommandStrings(commands)
	want := []string{
		"ip netns exec mesh-ns ip link show phvmesh",
		"ip netns exec mesh-ns ip link add phvmesh type veth peer name phvpeer",
		"ip netns exec mesh-ns ip link set phvmesh addrgenmode none",
		"ip netns exec mesh-ns ip link set phvmesh up",
		"ip netns exec mesh-ns ip link set phvpeer netns 1",
		"ip link set phvpeer addrgenmode none",
		"ip link set phvpeer up",
		"ip netns exec mesh-ns ip addr show phvmesh",
		"ip netns exec mesh-ns ip addr replace 169.254.1.1/30 dev phvmesh",
		"ip addr show phvpeer",
		"ip addr replace 169.254.1.2/30 dev phvpeer",
		"ip netns exec mesh-ns sysctl -w net.ipv4.conf.phvmesh.forwarding=1",
		"ip netns exec mesh-ns sysctl -w net.ipv6.conf.phvmesh.forwarding=1",
		"sysctl -w net.ipv4.conf.phvpeer.forwarding=1",
		"sysctl -w net.ipv6.conf.phvpeer.forwarding=1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("commands:\n got %#v\nwant %#v", got, want)
	}
}

func TestExecVethManagerSetsForwardingOnBothEndsInSeparateNetns(t *testing.T) {
	var commands []vethRecordedCommand
	m := &ExecVethManager{
		runner: func(_ context.Context, name string, args ...string) *exec.Cmd {
			commands = append(commands, vethRecordedCommand{name: name, args: append([]string(nil), args...)})
			if name == "ip" && strings.Contains(strings.Join(args, " "), "link show") {
				return exec.Command("false")
			}
			return exec.Command("true")
		},
	}

	spec := VethSpec{
		MeshInterface: "phvmesh",
		PeerInterface: "phvpeer",
		MeshNetns:     "mesh-ns",
		PeerNetns:     "peer-ns",
	}
	if err := m.EnsureVethPair(context.Background(), spec); err != nil {
		t.Fatalf("EnsureVethPair: %v", err)
	}

	got := vethCommandStrings(commands)
	wantPrefix := []string{
		"ip netns exec mesh-ns ip link show phvmesh",
		"ip netns exec mesh-ns ip link add phvmesh type veth peer name phvpeer",
		"ip netns exec mesh-ns ip link set phvmesh addrgenmode none",
		"ip netns exec mesh-ns ip link set phvmesh up",
		"ip netns exec mesh-ns ip link set phvpeer netns peer-ns",
		"ip netns exec peer-ns ip link set phvpeer addrgenmode none",
		"ip netns exec peer-ns ip link set phvpeer up",
		"ip netns exec mesh-ns sysctl -w net.ipv4.conf.phvmesh.forwarding=1",
		"ip netns exec mesh-ns sysctl -w net.ipv6.conf.phvmesh.forwarding=1",
		"ip netns exec peer-ns sysctl -w net.ipv4.conf.phvpeer.forwarding=1",
		"ip netns exec peer-ns sysctl -w net.ipv6.conf.phvpeer.forwarding=1",
	}
	if !reflect.DeepEqual(got, wantPrefix) {
		t.Fatalf("commands:\n got %#v\nwant %#v", got, wantPrefix)
	}
}

func TestExecVethManagerReturnsSysctlError(t *testing.T) {
	m := &ExecVethManager{
		runner: func(_ context.Context, name string, args ...string) *exec.Cmd {
			if name == "sysctl" {
				return exec.Command("false")
			}
			return exec.Command("true")
		},
	}

	spec := VethSpec{
		MeshInterface: "phvmesh",
		PeerInterface: "phvpeer",
		MeshNetns:     "mesh-ns",
		PeerNetns:     "",
	}
	err := m.EnsureVethPair(context.Background(), spec)
	if err == nil {
		t.Fatal("expected sysctl failure")
	}
	if !strings.Contains(err.Error(), "sysctl") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func vethCommandStrings(commands []vethRecordedCommand) []string {
	var out []string
	for _, cmd := range commands {
		out = append(out, strings.TrimSpace(cmd.name+" "+strings.Join(cmd.args, " ")))
	}
	return out
}
