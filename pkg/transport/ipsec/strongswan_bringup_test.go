package ipsec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestStrongSwanDriverIKEBringupSmoke brings up a real IKEv2/IPsec SA between
// two charon instances running in separate network namespaces, creates XFRM
// interfaces, assigns tunnel addresses, and verifies bidirectional ping.
func TestStrongSwanDriverIKEBringupSmoke(t *testing.T) {
	if os.Getenv("HIGGS_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set HIGGS_IPSEC_XFRM_SMOKE=1 to run the root/system StrongSwan smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	suffix := time.Now().UTC().Format("20060102150405")
	nsA := "higgs-ike-a-" + suffix
	nsB := "higgs-ike-b-" + suffix
	viciA := "/tmp/charon-" + nsA + ".vici"
	viciB := "/tmp/charon-" + nsB + ".vici"

	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", nsA).Run()
		_ = exec.Command("ip", "netns", "delete", nsB).Run()
		_ = os.Remove(viciA)
		_ = os.Remove(viciB)
	})

	// Create network namespaces and a veth pair connecting them.
	runIP(t, ctx, "netns", "add", nsA)
	runIP(t, ctx, "netns", "add", nsB)
	runIP(t, ctx, "link", "add", "hgvetha", "type", "veth", "peer", "name", "hgvethb")
	runIP(t, ctx, "link", "set", "hgvetha", "netns", nsA)
	runIP(t, ctx, "link", "set", "hgvethb", "netns", nsB)
	for _, args := range [][]string{
		{"netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
		{"netns", "exec", nsA, "ip", "addr", "add", "192.0.2.1/30", "dev", "hgvetha"},
		{"netns", "exec", nsB, "ip", "addr", "add", "192.0.2.2/30", "dev", "hgvethb"},
		{"netns", "exec", nsA, "ip", "link", "set", "hgvetha", "up"},
		{"netns", "exec", nsB, "ip", "link", "set", "hgvethb", "up"},
	} {
		runIP(t, ctx, args...)
	}

	// Start charon in each namespace with a dedicated VICI socket and a
	// private piddir bind-mounted over /run so multiple instances do not
	// conflict on /run/charon.pid.
	confA, err := writeStrongSwanConf(viciA)
	if err != nil {
		t.Fatalf("write strongswan.conf A: %v", err)
	}
	confB, err := writeStrongSwanConf(viciB)
	if err != nil {
		t.Fatalf("write strongswan.conf B: %v", err)
	}
	piddirA, err := os.MkdirTemp("", "higgs-piddir-a-*")
	if err != nil {
		t.Fatalf("create piddir A: %v", err)
	}
	piddirB, err := os.MkdirTemp("", "higgs-piddir-b-*")
	if err != nil {
		t.Fatalf("create piddir B: %v", err)
	}

	logA, err := os.CreateTemp("", "higgs-charon-a-*.log")
	if err != nil {
		t.Fatalf("create log A: %v", err)
	}
	logB, err := os.CreateTemp("", "higgs-charon-b-*.log")
	if err != nil {
		t.Fatalf("create log B: %v", err)
	}

	charonA := startCharonInNetNS(ctx, t, nsA, piddirA, confA, logA)
	charonB := startCharonInNetNS(ctx, t, nsB, piddirB, confB, logB)
	defer func() {
		_ = charonA.Process.Kill()
		_ = charonB.Process.Kill()
		_ = charonA.Wait()
		_ = charonB.Wait()
		_ = os.Remove(confA)
		_ = os.Remove(confB)
		_ = os.RemoveAll(piddirA)
		_ = os.RemoveAll(piddirB)
		_ = logA.Close()
		_ = logB.Close()
		_ = os.Remove(logA.Name())
		_ = os.Remove(logB.Name())
	}()
	dumpLogsOnFail := func() {
		_ = logA.Sync()
		_ = logB.Sync()
		t.Logf("--- charon A log ---")
		if data, err := os.ReadFile(logA.Name()); err == nil {
			t.Logf("%s", string(data))
		}
		t.Logf("--- charon B log ---")
		if data, err := os.ReadFile(logB.Name()); err == nil {
			t.Logf("%s", string(data))
		}
	}
	defer func() {
		if t.Failed() {
			dumpLogsOnFail()
		}
	}()

	clientA, err := waitForVICI(ctx, viciA)
	if err != nil {
		t.Fatalf("connect to charon A VICI: %v", err)
	}
	defer clientA.Close()
	clientB, err := waitForVICI(ctx, viciB)
	if err != nil {
		t.Fatalf("connect to charon B VICI: %v", err)
	}
	defer clientB.Close()

	// Generate transport keys for both peers.
	localPrivA, localPubA, err := generateECDSAKeyPair()
	if err != nil {
		t.Fatalf("generate key A: %v", err)
	}
	localPrivB, localPubB, err := generateECDSAKeyPair()
	if err != nil {
		t.Fatalf("generate key B: %v", err)
	}

	const ifID = uint32(424244)
	iface := "hgsike0"
	transportAtoB := "ipsec-ike-a-b"
	transportBtoA := "ipsec-ike-b-a"

	specA := TransportLinkSpec{
		LocalZone:                "node-a.",
		PeerZone:                 "node-b.",
		OverlayID:                "main",
		Provider:                 ProviderStrongSwan,
		TransportID:              transportAtoB,
		Direction:                DirectionOutbound,
		PathMode:                 PathModeFamilyRedundant,
		IKEIdentity:              "node-a.",
		LocalAddress:             "192.0.2.1",
		ContactPoints:            []ContactPoint{{Address: "192.0.2.2", IKEPort: DefaultIKEPort, NATTPort: DefaultNATTPort}},
		XFRMIfID:                 ifID,
		InterfaceName:            iface,
		LocalTunnelAddr:          netip.MustParseAddr("10.44.0.1"),
		PeerTunnelAddr:           netip.MustParseAddr("10.44.0.2"),
		NetNS:                    nsA,
		LocalPrivateKey:          localPrivA,
		LocalPrivateKeyAlgorithm: AlgorithmECDSAP256,
		PeerPublicKey:            localPubB,
	}
	specB := TransportLinkSpec{
		LocalZone:                "node-b.",
		PeerZone:                 "node-a.",
		OverlayID:                "main",
		Provider:                 ProviderStrongSwan,
		TransportID:              transportBtoA,
		Direction:                DirectionOutbound,
		PathMode:                 PathModeFamilyRedundant,
		IKEIdentity:              "node-b.",
		LocalAddress:             "192.0.2.2",
		ContactPoints:            []ContactPoint{{Address: "192.0.2.1", IKEPort: DefaultIKEPort, NATTPort: DefaultNATTPort}},
		XFRMIfID:                 ifID,
		InterfaceName:            iface,
		LocalTunnelAddr:          netip.MustParseAddr("10.44.0.2"),
		PeerTunnelAddr:           netip.MustParseAddr("10.44.0.1"),
		NetNS:                    nsB,
		LocalPrivateKey:          localPrivB,
		LocalPrivateKeyAlgorithm: AlgorithmECDSAP256,
		PeerPublicKey:            localPubA,
	}

	keyDirA := t.TempDir()
	keyDirB := t.TempDir()
	ipsecA := &StrongSwanDriver{VICI: clientA, KeyDir: keyDirA}
	ipsecB := &StrongSwanDriver{VICI: clientB, KeyDir: keyDirB}
	xfrmA := NewSystemXFRMDriver(NetNSSpec{Kind: NetNSName, Name: nsA, Create: false})
	xfrmB := NewSystemXFRMDriver(NetNSSpec{Kind: NetNSName, Name: nsB, Create: false})

	if _, err := ApplyTransportLink(ctx, ipsecA, xfrmA, specA, NetNSSpec{Kind: NetNSName, Name: nsA}); err != nil {
		t.Fatalf("apply transport link A: %v", err)
	}
	if _, err := ApplyTransportLink(ctx, ipsecB, xfrmB, specB, NetNSSpec{Kind: NetNSName, Name: nsB}); err != nil {
		t.Fatalf("apply transport link B: %v", err)
	}

	// Wait until both sides report an established SA. Both connections use
	// start_action=start, so after both configs are loaded the side that
	// initiates second (B) will find a matching responder on A; A then
	// processes B's request and also ends up with an established SA.
	if err := waitForSA(ctx, clientA, transportAtoB); err != nil {
		t.Fatalf("wait for SA on A: %v", err)
	}
	if err := waitForSA(ctx, clientB, transportBtoA); err != nil {
		t.Fatalf("wait for SA on B: %v", err)
	}

	// Add host routes so tunnel ping traverses the XFRM interface.
	runIP(t, ctx, "netns", "exec", nsA, "ip", "route", "replace", "10.44.0.2/32", "dev", iface, "src", "10.44.0.1")
	runIP(t, ctx, "netns", "exec", nsB, "ip", "route", "replace", "10.44.0.1/32", "dev", iface, "src", "10.44.0.2")

	if out, err := execCommand(ctx, "ip", "netns", "exec", nsA, "ping", "-c", "1", "-W", "3", "10.44.0.2"); err != nil {
		t.Fatalf("tunnel ping A->B failed: %v\n%s", err, string(out))
	}
	if out, err := execCommand(ctx, "ip", "netns", "exec", nsB, "ping", "-c", "1", "-W", "3", "10.44.0.1"); err != nil {
		t.Fatalf("tunnel ping B->A failed: %v\n%s", err, string(out))
	}

	t.Logf("IKE bring-up succeeded; bidirectional tunnel ping passed")
}

func generateECDSAKeyPair() (privDER, pubDER []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privDER, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err = x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privDER, pubDER, nil
}

func writeStrongSwanConf(viciSocket string) (string, error) {
	f, err := os.CreateTemp("", "strongswan-*.conf")
	if err != nil {
		return "", err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, `charon {
	install_routes = no
	install_virtual_ip = no
	plugins {
		vici {
			socket = unix://%s
		}
	}
}
`, viciSocket)
	if err != nil {
		return "", err
	}
	return f.Name(), nil
}

func startCharonInNetNS(ctx context.Context, t *testing.T, ns, piddir, conf string, logFile *os.File) *exec.Cmd {
	t.Helper()
	script := fmt.Sprintf("mkdir -p /run && mount --bind %s /run && STRONGSWAN_CONF=%s exec charon", piddir, conf)
	cmd := exec.CommandContext(ctx, "unshare", "-m", "ip", "netns", "exec", ns, "bash", "-c", script)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start charon in %s: %v", ns, err)
	}
	return cmd
}

func waitForVICI(ctx context.Context, socket string) (*GoviciClient, error) {
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for vici socket %s", socket)
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}
	var lastErr error
	for {
		client, err := NewGoviciClient(socket)
		if err == nil {
			return client, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("connect to %s: %w", socket, lastErr)
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func waitForSA(ctx context.Context, client *GoviciClient, name string) error {
	for {
		events, err := client.CallStreaming(ctx, "list-sas", "list-sa", map[string]any{"ike": name})
		if err != nil {
			return err
		}
		established := false
		for _, event := range events {
			if saEstablished(event) {
				established = true
				break
			}
		}
		if established {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for SA %s", name)
		default:
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func saEstablished(raw map[string]any) bool {
	for _, v := range raw {
		sa, ok := v.(map[string]any)
		if !ok {
			continue
		}
		state := stringValue(sa["state"])
		if strings.EqualFold(state, "ESTABLISHED") {
			return true
		}
		children, _ := sa["child-sas"].(map[string]any)
		for _, cv := range children {
			child, ok := cv.(map[string]any)
			if !ok {
				continue
			}
			if stringValue(child["state"]) == "INSTALLED" {
				return true
			}
		}
	}
	return false
}
