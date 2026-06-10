package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

type recordedCommand struct {
	name string
	args []string
}

func TestSystemXFRMDriverCreatesNamedNamespaceAndXFRMInterface(t *testing.T) {
	var commands []recordedCommand
	driver := SystemXFRMDriver{
		DefaultNetNS: NetNSSpec{Kind: NetNSName, Name: "h2", Create: true},
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, recordedCommand{name: name, args: append([]string(nil), args...)})
			if reflect.DeepEqual(args, []string{"netns", "exec", "h2", "true"}) {
				return nil, errors.New("missing")
			}
			if strings.Join(args, " ") == "netns exec h2 ip link show dev hgs1" {
				return nil, errors.New("missing")
			}
			if strings.Join(args, " ") == "link show dev hgs1" {
				return nil, errors.New("missing")
			}
			return []byte("ok"), nil
		},
	}
	spec := TransportLinkSpec{
		TransportID:     "ipsec-1",
		InterfaceName:   "hgs1",
		XFRMIfID:        42,
		NetNS:           "h2",
		LocalTunnelAddr: netip.MustParseAddr("fd00:1234::1"),
	}
	if err := driver.EnsureInterface(context.Background(), spec); err != nil {
		t.Fatalf("EnsureInterface: %v", err)
	}
	if err := driver.AssignAddress(context.Background(), "hgs1", "fd00:1234::1/64"); err != nil {
		t.Fatalf("AssignAddress: %v", err)
	}
	got := commandStrings(commands)
	want := []string{
		"ip netns exec h2 true",
		"ip netns add h2",
		"ip netns exec h2 ip link show dev hgs1",
		"ip link show dev hgs1",
		"ip link add hgs1 type xfrm if_id 42",
		"ip link set hgs1 netns h2",
		"ip netns exec h2 ip link set dev hgs1 up",
		"ip netns exec h2 ip addr replace fd00:1234::1/64 dev hgs1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("commands:\n got %#v\nwant %#v", got, want)
	}
}

func TestSystemXFRMDriverRejectsMissingNonCreateNamespace(t *testing.T) {
	driver := SystemXFRMDriver{
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			return nil, errors.New("missing")
		},
	}
	err := driver.EnsureNamespace(context.Background(), NetNSSpec{Kind: NetNSName, Name: "manual", Create: false})
	if err == nil || !strings.Contains(err.Error(), "create=false") {
		t.Fatalf("EnsureNamespace err = %v", err)
	}
}

func TestSystemXFRMDriverRejectsPathNetNSInterfaceMove(t *testing.T) {
	driver := SystemXFRMDriver{
		Stat: func(string) error { return nil },
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if strings.Join(args, " ") == "link show dev hgs1" {
				return nil, errors.New("missing")
			}
			return []byte("ok"), nil
		},
	}
	spec := TransportLinkSpec{InterfaceName: "hgs1", XFRMIfID: 7, NetNS: "/run/netns/h2"}
	err := driver.EnsureInterface(context.Background(), spec)
	if err == nil || !strings.Contains(err.Error(), "path netns") {
		t.Fatalf("EnsureInterface err = %v", err)
	}
}

func commandStrings(commands []recordedCommand) []string {
	var out []string
	for _, cmd := range commands {
		out = append(out, strings.TrimSpace(cmd.name+" "+strings.Join(cmd.args, " ")))
	}
	return out
}
