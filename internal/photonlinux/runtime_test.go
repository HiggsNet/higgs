package photonlinux

import (
	"context"
	"testing"

	transportipsec "github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestRuntimeOwnsIPsecCleanupDependencies(t *testing.T) {
	driver := &transportipsec.DryRunDriver{}
	runtime := NewRuntime(RuntimeOptions{IPsecDriver: driver, XFRMDriver: driver})
	remaining, cleaned, err := runtime.CleanupIPsecLinks(context.Background(), nil, []string{"already-missing"})
	if err != nil {
		t.Fatalf("CleanupIPsecLinks: %v", err)
	}
	if cleaned != 0 || len(remaining) != 0 {
		t.Fatalf("cleanup result = (%d, %v), want empty idempotent result", cleaned, remaining)
	}
}

func TestRuntimeClosesOwnedDependenciesOnce(t *testing.T) {
	closed := 0
	runtime := NewRuntime(RuntimeOptions{Close: func() error {
		closed++
		return nil
	}})
	if err := runtime.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if closed != 1 {
		t.Fatalf("close calls = %d, want 1", closed)
	}
}
