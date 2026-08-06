package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishResolvedServiceOrdersReadinessACLRouteAndRecord(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	outputDir := t.TempDir()
	manifest := resolvedManifest{
		ManagedZone: "node-a.catofes.",
		OutputDir:   outputDir,
		SOCKS5: resolvedSOCKS5{
			Port:       uint16(listener.Addr().(*net.TCPAddr).Port),
			ConfigHash: "test-config",
			AllowZones: []string{"*.catofes."},
			Networks: map[string]resolvedRoleAddrs{
				"cn": {SOCKS: "127.0.0.1", H2: "127.0.0.1"},
			},
			Endpoints: []resolvedEndpoint{{
				Network: "cn", Region: "cn", Address: "127.0.0.1",
				Port: uint16(listener.Addr().(*net.TCPAddr).Port), Assignment: "10.42.0.0/24", Shared: true,
			}},
		},
	}
	if err := writeSOCKS5Lock(filepath.Join(outputDir, "socks5", "resolved.json"), renderedSOCKS5Lock{resolvedSOCKS5: manifest.SOCKS5, ManagedZone: manifest.ManagedZone}); err != nil {
		t.Fatalf("write rendered lock: %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "photon.log")
	binary := writeFakePhoton(t, logPath)
	if err := publishResolvedService(binary, manifest); err != nil {
		t.Fatalf("publishResolvedService: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake Photon log: %v", err)
	}
	lines := strings.Fields(strings.TrimSpace(string(data)))
	want := []string{
		"firewall endpoint apply socks5-cn --destination 127.0.0.1 --scope ip --allow-zone *.catofes.",
		"firewall endpoint apply h2-cn --destination 127.0.0.1 --scope ip --allow-zone *.catofes.",
		"route announce node-a.catofes. 10.42.0.0/24",
		"service publish --endpoint cn,127.0.0.1," + fmt.Sprint(listener.Addr().(*net.TCPAddr).Port),
	}
	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(got) != len(want) || strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Photon calls = %q (fields %v), want %q", got, lines, want)
	}
	if _, err := loadPublishedSOCKS5(outputDir); err != nil {
		t.Fatalf("published lock: %v", err)
	}
}

func TestPublishResolvedServiceDoesNotPublishWhenEndpointIsNotReady(t *testing.T) {
	outputDir := t.TempDir()
	manifest := resolvedManifest{
		ManagedZone: "node-a.catofes.",
		OutputDir:   outputDir,
		SOCKS5: resolvedSOCKS5{
			Port:       1,
			ConfigHash: "test-config",
			Networks: map[string]resolvedRoleAddrs{
				"main": {SOCKS: "127.0.0.1", H2: "127.0.0.1"},
			},
			Endpoints: []resolvedEndpoint{{Network: "main", Region: "local", Address: "127.0.0.1", Port: 1, Assignment: "10.42.0.0/24"}},
		},
	}
	if err := writeSOCKS5Lock(filepath.Join(outputDir, "socks5", "resolved.json"), renderedSOCKS5Lock{resolvedSOCKS5: manifest.SOCKS5, ManagedZone: manifest.ManagedZone}); err != nil {
		t.Fatalf("write rendered lock: %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "photon.log")
	err := publishResolvedService(writeFakePhoton(t, logPath), manifest)
	if err == nil || !strings.Contains(err.Error(), "TCP readiness check failed") {
		t.Fatalf("publish error = %v, want readiness failure", err)
	}
	if data, readErr := os.ReadFile(logPath); readErr == nil && len(data) != 0 {
		t.Fatalf("Photon was called despite failed readiness: %q", data)
	}
}

func writeFakePhoton(t *testing.T, logPath string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "photon")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + logPath + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake Photon: %v", err)
	}
	return path
}
