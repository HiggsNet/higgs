package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveAndRenderManifest(t *testing.T) {
	output := t.TempDir()
	configured := manifest{
		Version: 1, OutputDir: output,
		Images: imageConfig{Gost: defaultGostImage, SmartDNS: defaultSmartDNSImage},
		Networks: map[string]networkConfig{
			"main": {IPv4: "local;172.30.0.0/24;172.30.0.128/28;172.30.0.1", IPv6: "auto;::/112;::100/120;::1"},
			"cn":   {IPv6: "assignment:fd42:2::/64;::/112;::100/120;::1"},
		},
		SOCKS5: socks5Config{Region: "cn-east", Publish: "main", Networks: map[string]string{"main": "::20", "cn": "::30"}},
	}
	_, err := resolveManifest(configured, []runtimeAssignment{{Prefix: "fd42:1::/64"}, {Prefix: "fd42:2::/64"}})
	if err == nil || !strings.Contains(err.Error(), "auto requires exactly one") {
		t.Fatalf("ambiguous auto error = %v", err)
	}
	configured.Networks["main"] = networkConfig{IPv4: configured.Networks["main"].IPv4, IPv6: "assignment:fd42:1::/64;::/112;::100/120;::1"}
	resolved, err := resolveManifest(configured, []runtimeAssignment{{Prefix: "fd42:1::/64"}, {Prefix: "fd42:2::/64"}})
	if err != nil {
		t.Fatalf("resolveManifest: %v", err)
	}
	service := resolved.SOCKS5
	if service.Address != "fd42:1::20" || service.Networks["main"].DNS != "fd42:1::21" || service.Networks["main"].H2 != "fd42:1::22" {
		t.Fatalf("resolved service = %#v", service)
	}
	if err := renderArtifacts(resolved); err != nil {
		t.Fatalf("renderArtifacts: %v", err)
	}
	networkCompose := readTestFile(t, filepath.Join(output, "networks", "docker-compose.yml"))
	if !strings.Contains(networkCompose, "name: higgs-main") || !strings.Contains(networkCompose, "fd42:1::/112") {
		t.Fatalf("network compose:\n%s", networkCompose)
	}
	serviceCompose := readTestFile(t, filepath.Join(output, "socks5", "docker-compose.yml"))
	for _, want := range []string{"name: higgs-socks5", "socks:", "dns:", "h2:", "ipv6_address: fd42:1::20", "ipv6_address: fd42:1::21", "ipv6_address: fd42:1::22"} {
		if !strings.Contains(serviceCompose, want) {
			t.Fatalf("service compose missing %q:\n%s", want, serviceCompose)
		}
	}
}

func TestResolveManifestRejectsDynamicRoleAddress(t *testing.T) {
	configured := manifest{
		Version: 1, OutputDir: t.TempDir(), Images: imageConfig{Gost: defaultGostImage, SmartDNS: defaultSmartDNSImage},
		Networks: map[string]networkConfig{"main": {IPv6: "assignment:fd42:1::/64;::/112;::100/120;::1"}},
		SOCKS5:   socks5Config{Region: "test", Publish: "main", Networks: map[string]string{"main": "::100"}},
	}
	_, err := resolveManifest(configured, []runtimeAssignment{{Prefix: "fd42:1::/64"}})
	if err == nil || !strings.Contains(err.Error(), "dynamic range") {
		t.Fatalf("error = %v", err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
