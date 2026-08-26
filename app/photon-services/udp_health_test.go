package main

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSOCKS5UDPDNSReadinessFallsBackAcrossResolvers(t *testing.T) {
	var calls []string
	err := checkSOCKS5UDPDNSWithProbe("[::1]:3128", resolverConfig{
		Servers: []string{"8.8.8.8", "1.1.1.1"},
	}, time.Second, func(_ string, target *net.UDPAddr, _ time.Duration) error {
		calls = append(calls, target.String())
		if target.IP.Equal(net.ParseIP("1.1.1.1")) {
			return nil
		}
		return errors.New("timeout")
	})
	if err != nil {
		t.Fatalf("checkSOCKS5UDPDNSWithProbe: %v", err)
	}
	want := []string{"8.8.8.8:53", "1.1.1.1:53"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("probe calls = %v, want %v", calls, want)
	}
}

func TestSOCKS5UDPDNSReadinessRetriesBoundedly(t *testing.T) {
	var calls []string
	err := checkSOCKS5UDPDNSWithProbe("[::1]:3128", resolverConfig{
		Servers: []string{"dns://8.8.8.8", "udp://1.1.1.1:53"},
	}, time.Second, func(_ string, target *net.UDPAddr, _ time.Duration) error {
		calls = append(calls, target.String())
		return errors.New("timeout")
	})
	if err == nil || !strings.Contains(err.Error(), "all SOCKS5 UDP DNS readiness probes failed") {
		t.Fatalf("readiness error = %v", err)
	}
	want := []string{
		"8.8.8.8:53", "1.1.1.1:53",
		"8.8.8.8:53", "1.1.1.1:53",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("probe calls = %v, want %v", calls, want)
	}
}

func TestUDPDNSProbeTargetsDeduplicatesResolvers(t *testing.T) {
	targets, err := udpDNSProbeTargets([]string{"8.8.8.8", "udp://8.8.8.8:53", "https://ignored.example/dns-query"})
	if err != nil {
		t.Fatalf("udpDNSProbeTargets: %v", err)
	}
	if len(targets) != 1 || targets[0].String() != "8.8.8.8:53" {
		t.Fatalf("targets = %v, want [8.8.8.8:53]", targets)
	}
}
