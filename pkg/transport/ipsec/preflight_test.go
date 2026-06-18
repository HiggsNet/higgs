package ipsec

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPreflightReadyWithExpectedDependencies(t *testing.T) {
	checker := fakePreflightChecker(true)
	result := checker.Run(context.Background(), PreflightOptions{})
	if !result.Ready() {
		t.Fatalf("Ready=false, errors=%v checks=%+v", result.Errors(), result.Checks)
	}
	if got := checkByName(t, result, "udp-ike-port"); !got.Skipped {
		t.Fatalf("udp check should be skipped by default: %+v", got)
	}
}

func TestPreflightReportsMissingRuntimeDependencies(t *testing.T) {
	checker := fakePreflightChecker(false)
	checker.Stat = func(string) error { return errors.New("missing") }
	checker.Command = func(_ context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("missing")
	}
	checker.ReadFile = func(string) ([]byte, error) { return nil, errors.New("missing") }
	result := checker.Run(context.Background(), PreflightOptions{})
	if result.Ready() {
		t.Fatalf("Ready=true for missing dependencies")
	}
	errs := strings.Join(result.Errors(), "\n")
	for _, want := range []string{"root-or-cap-net-admin", "vici-socket", "iproute2-ip", "swanctl", "charon", "kernel-xfrm", "iproute2-xfrm-interface"} {
		if !strings.Contains(errs, want) {
			t.Fatalf("errors %q do not contain %q", errs, want)
		}
	}
}

func TestPreflightChecksUDPPortsWhenRequested(t *testing.T) {
	var ports []uint16
	checker := fakePreflightChecker(true)
	checker.ListenUDP = func(_ context.Context, port uint16) error {
		ports = append(ports, port)
		if port == 4500 {
			return errors.New("busy")
		}
		return nil
	}
	result := checker.Run(context.Background(), PreflightOptions{IKEPort: 500, NATTPort: 4500, RequireUDP: true})
	if result.Ready() {
		t.Fatalf("Ready=true with busy NAT-T port")
	}
	if len(ports) != 2 || ports[0] != 500 || ports[1] != 4500 {
		t.Fatalf("ports checked = %+v", ports)
	}
	if got := checkByName(t, result, "udp-natt-port"); got.OK || got.Skipped {
		t.Fatalf("udp-natt-port = %+v", got)
	}
}

func TestPreflightReadsCapNetAdminFromProcStatus(t *testing.T) {
	checker := fakePreflightChecker(true)
	checker.EUID = func() int { return 1000 }
	checker.ReadFile = func(path string) ([]byte, error) {
		if path == "/proc/self/status" {
			return []byte("Name:\thiggs\nCapEff:\t0000000000001000\n"), nil
		}
		return []byte("ok"), nil
	}
	result := checker.Run(context.Background(), PreflightOptions{})
	if got := checkByName(t, result, "root-or-cap-net-admin"); !got.OK {
		t.Fatalf("root-or-cap-net-admin = %+v", got)
	}
}

func fakePreflightChecker(hasPrivilege bool) PreflightChecker {
	return PreflightChecker{
		GOOS: "linux",
		ReadFile: func(string) ([]byte, error) {
			return []byte("ok"), nil
		},
		Stat: func(string) error {
			return nil
		},
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			return []byte("ok"), nil
		},
		EUID: func() int {
			if hasPrivilege {
				return 0
			}
			return 1000
		},
		CapNetAdmin: func() (bool, error) {
			return hasPrivilege, nil
		},
		ListenUDP: func(context.Context, uint16) error {
			return nil
		},
	}
}

func checkByName(t *testing.T, result PreflightResult, name string) PreflightCheck {
	t.Helper()
	for _, check := range result.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("missing check %q in %+v", name, result.Checks)
	return PreflightCheck{}
}
