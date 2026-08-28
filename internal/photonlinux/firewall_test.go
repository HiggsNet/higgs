package photonlinux

import (
	"testing"

	"github.com/HiggsNet/photon/pkg/firewall"
	transportipsec "github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestFirewallDriverResolvesConfiguredNamespace(t *testing.T) {
	dryRun := &transportipsec.DryRunDriver{}
	runtime, err := NewRuntime(RuntimeOptions{
		IPsecDriver: dryRun,
		XFRMDriver:  dryRun,
		NetworkNamespaces: map[string]transportipsec.NetNSSpec{
			"default": {Kind: transportipsec.NetNSName, Name: "photontesth2", Create: true},
		},
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}

	driver, err := runtime.newFirewallDriver(firewall.FirewallInstanceSpec{ID: "photon", NetNS: "default"}, firewall.BackendNFT)
	if err != nil {
		t.Fatalf("newFirewallDriver: %v", err)
	}
	nft, ok := driver.(*firewall.NFTDriver)
	if !ok {
		t.Fatalf("driver type = %T, want *firewall.NFTDriver", driver)
	}
	if nft.NetNS != "photontesth2" {
		t.Fatalf("driver netns = %q, want photontesth2", nft.NetNS)
	}

	hostDriver, err := runtime.newFirewallDriver(firewall.FirewallInstanceSpec{ID: "host", IsHost: true}, firewall.BackendIptables)
	if err != nil {
		t.Fatalf("host newFirewallDriver: %v", err)
	}
	iptables, ok := hostDriver.(*firewall.IPTablesDriver)
	if !ok {
		t.Fatalf("host driver type = %T, want *firewall.IPTablesDriver", hostDriver)
	}
	if iptables.NetNS != "" {
		t.Fatalf("host driver netns = %q, want empty host namespace", iptables.NetNS)
	}
}

func TestFirewallDriverRejectsUnknownNamespace(t *testing.T) {
	dryRun := &transportipsec.DryRunDriver{}
	runtime, err := NewRuntime(RuntimeOptions{IPsecDriver: dryRun, XFRMDriver: dryRun})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if _, err := runtime.newFirewallDriver(firewall.FirewallInstanceSpec{ID: "missing", NetNS: "missing"}, firewall.BackendNFT); err == nil {
		t.Fatal("newFirewallDriver accepted an unknown namespace")
	}
}
