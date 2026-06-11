package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type recordedCommand struct {
	name string
	args []string
}

func TestSystemXFRMDriverCreatesXFRMInterfaceInsideNamedNamespace(t *testing.T) {
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
		"ip netns exec h2 ip link add hgs1 type xfrm if_id 42",
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

func TestSystemXFRMDriverIntegrationSmoke(t *testing.T) {
	if os.Getenv("HIGGS_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set HIGGS_IPSEC_XFRM_SMOKE=1 to run the root/system XFRM smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ns := "higgs-xfrm-smoke-" + time.Now().UTC().Format("20060102150405")
	iface := "hgsxfrm0"
	driver := NewSystemXFRMDriver(NetNSSpec{Kind: NetNSName, Name: ns, Create: true})
	spec := TransportLinkSpec{
		TransportID:     "ipsec-smoke-a-b",
		InterfaceName:   iface,
		XFRMIfID:        424242,
		NetNS:           ns,
		LocalTunnelAddr: netip.MustParseAddr("fd00:4242::1"),
	}
	t.Cleanup(func() {
		_ = driver.DeleteInterface(context.Background(), iface)
		_, _ = execCommand(context.Background(), "ip", "netns", "delete", ns)
	})

	if err := driver.EnsureInterface(ctx, spec); err != nil {
		t.Fatalf("EnsureInterface: %v", err)
	}
	if err := driver.AssignAddress(ctx, iface, "fd00:4242::1/64"); err != nil {
		t.Fatalf("AssignAddress: %v", err)
	}
	if _, err := execCommand(ctx, "ip", "netns", "exec", ns, "ip", "link", "show", "dev", iface); err != nil {
		t.Fatalf("link not visible in namespace: %v", err)
	}
	if _, err := execCommand(ctx, "ip", "netns", "exec", ns, "ip", "addr", "show", "dev", iface); err != nil {
		t.Fatalf("address not visible in namespace: %v", err)
	}
	if err := driver.DeleteInterface(ctx, iface); err != nil {
		t.Fatalf("DeleteInterface: %v", err)
	}
	if _, err := execCommand(ctx, "ip", "netns", "exec", ns, "ip", "link", "show", "dev", iface); err == nil {
		t.Fatalf("interface %s still exists after DeleteInterface", iface)
	}
}

func TestSystemXFRMDriverPeerTunnelPingSmoke(t *testing.T) {
	if os.Getenv("HIGGS_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set HIGGS_IPSEC_XFRM_SMOKE=1 to run the root/system XFRM smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "higgs-xfrm-a-" + suffix
	nsB := "higgs-xfrm-b-" + suffix
	iface := "hgsxfrm0"
	const ifID = uint32(424243)
	const reqID = uint32(424243)
	t.Cleanup(func() {
		_, _ = execCommand(context.Background(), "ip", "netns", "delete", nsA)
		_, _ = execCommand(context.Background(), "ip", "netns", "delete", nsB)
	})

	runIP(t, ctx, "netns", "add", nsA)
	runIP(t, ctx, "netns", "add", nsB)
	runIP(t, ctx, "link", "add", "hgvetha", "type", "veth", "peer", "name", "hgvethb")
	runIP(t, ctx, "link", "set", "hgvetha", "netns", nsA)
	runIP(t, ctx, "link", "set", "hgvethb", "netns", nsB)
	runIP(t, ctx, "netns", "exec", nsA, "ip", "link", "set", "lo", "up")
	runIP(t, ctx, "netns", "exec", nsB, "ip", "link", "set", "lo", "up")
	runIP(t, ctx, "netns", "exec", nsA, "ip", "addr", "add", "192.0.2.1/30", "dev", "hgvetha")
	runIP(t, ctx, "netns", "exec", nsB, "ip", "addr", "add", "192.0.2.2/30", "dev", "hgvethb")
	runIP(t, ctx, "netns", "exec", nsA, "ip", "link", "set", "hgvetha", "up")
	runIP(t, ctx, "netns", "exec", nsB, "ip", "link", "set", "hgvethb", "up")

	driverA := NewSystemXFRMDriver(NetNSSpec{Kind: NetNSName, Name: nsA, Create: true})
	driverB := NewSystemXFRMDriver(NetNSSpec{Kind: NetNSName, Name: nsB, Create: true})
	specA := TransportLinkSpec{
		TransportID:     "ipsec-smoke-a-b",
		InterfaceName:   iface,
		XFRMIfID:        ifID,
		NetNS:           nsA,
		LocalTunnelAddr: netip.MustParseAddr("10.44.0.1"),
	}
	specB := TransportLinkSpec{
		TransportID:     "ipsec-smoke-b-a",
		InterfaceName:   iface,
		XFRMIfID:        ifID,
		NetNS:           nsB,
		LocalTunnelAddr: netip.MustParseAddr("10.44.0.2"),
	}
	if err := driverA.EnsureInterface(ctx, specA); err != nil {
		t.Fatalf("EnsureInterface(A): %v", err)
	}
	if err := driverB.EnsureInterface(ctx, specB); err != nil {
		t.Fatalf("EnsureInterface(B): %v", err)
	}
	if err := driverA.AssignAddress(ctx, iface, "10.44.0.1/30"); err != nil {
		t.Fatalf("AssignAddress(A): %v", err)
	}
	if err := driverB.AssignAddress(ctx, iface, "10.44.0.2/30"); err != nil {
		t.Fatalf("AssignAddress(B): %v", err)
	}

	installPeerXFRM(t, ctx, nsA, ifID, reqID, "192.0.2.1", "192.0.2.2", "10.44.0.1", "10.44.0.2", "0x100", "0x200")
	installPeerXFRM(t, ctx, nsB, ifID, reqID, "192.0.2.2", "192.0.2.1", "10.44.0.2", "10.44.0.1", "0x200", "0x100")
	runIP(t, ctx, "netns", "exec", nsA, "ip", "route", "replace", "10.44.0.2/32", "dev", iface, "src", "10.44.0.1")
	runIP(t, ctx, "netns", "exec", nsB, "ip", "route", "replace", "10.44.0.1/32", "dev", iface, "src", "10.44.0.2")

	if out, err := execCommand(ctx, "ip", "netns", "exec", nsA, "ping", "-c", "1", "-W", "2", "10.44.0.2"); err != nil {
		t.Fatalf("tunnel ping A->B failed: %v\n%s", err, string(out))
	}
	if out, err := execCommand(ctx, "ip", "netns", "exec", nsB, "ping", "-c", "1", "-W", "2", "10.44.0.1"); err != nil {
		t.Fatalf("tunnel ping B->A failed: %v\n%s", err, string(out))
	}
}

func commandStrings(commands []recordedCommand) []string {
	var out []string
	for _, cmd := range commands {
		out = append(out, strings.TrimSpace(cmd.name+" "+strings.Join(cmd.args, " ")))
	}
	return out
}

func installPeerXFRM(t *testing.T, ctx context.Context, ns string, ifID, reqID uint32, localUnderlay, peerUnderlay, localTunnel, peerTunnel, outboundSPI, inboundSPI string) {
	t.Helper()
	authKey := "0x1111111111111111111111111111111111111111111111111111111111111111"
	encKey := "0x22222222222222222222222222222222"
	runIP(t, ctx, "netns", "exec", ns, "ip", "xfrm", "state", "add",
		"src", localUnderlay, "dst", peerUnderlay,
		"proto", "esp", "spi", outboundSPI, "reqid", fmt.Sprintf("%d", reqID),
		"mode", "tunnel", "if_id", fmt.Sprintf("%d", ifID),
		"auth", "hmac(sha256)", authKey, "enc", "cbc(aes)", encKey)
	runIP(t, ctx, "netns", "exec", ns, "ip", "xfrm", "state", "add",
		"src", peerUnderlay, "dst", localUnderlay,
		"proto", "esp", "spi", inboundSPI, "reqid", fmt.Sprintf("%d", reqID),
		"mode", "tunnel", "if_id", fmt.Sprintf("%d", ifID),
		"auth", "hmac(sha256)", authKey, "enc", "cbc(aes)", encKey)
	runIP(t, ctx, "netns", "exec", ns, "ip", "xfrm", "policy", "add",
		"dir", "out", "if_id", fmt.Sprintf("%d", ifID),
		"src", localTunnel+"/32", "dst", peerTunnel+"/32",
		"tmpl", "src", localUnderlay, "dst", peerUnderlay, "proto", "esp",
		"reqid", fmt.Sprintf("%d", reqID), "mode", "tunnel")
	runIP(t, ctx, "netns", "exec", ns, "ip", "xfrm", "policy", "add",
		"dir", "in", "if_id", fmt.Sprintf("%d", ifID),
		"src", peerTunnel+"/32", "dst", localTunnel+"/32",
		"tmpl", "src", peerUnderlay, "dst", localUnderlay, "proto", "esp",
		"reqid", fmt.Sprintf("%d", reqID), "mode", "tunnel")
}

func runIP(t *testing.T, ctx context.Context, args ...string) {
	t.Helper()
	if out, err := execCommand(ctx, "ip", args...); err != nil {
		t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, string(out))
	}
}
