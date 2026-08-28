package photonlinux

import (
	"context"
	"testing"

	"github.com/HiggsNet/photon/pkg/health"
	transportipsec "github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type closeTrackingHealthProber struct {
	closed int
}

func (*closeTrackingHealthProber) Type() string { return health.ProbeTypeICMP }

func (*closeTrackingHealthProber) Probe(context.Context, health.ProbeTarget, health.ProbeConfig) health.ProbeResult {
	return health.ProbeResult{}
}

func (p *closeTrackingHealthProber) Close() { p.closed++ }

type lifecycleDriver struct {
	transportipsec.DryRunDriver
	events chan transportipsec.VICIEvent
}

func (d *lifecycleDriver) SubscribeLifecycleEvents(context.Context) (<-chan transportipsec.VICIEvent, func(), error) {
	return d.events, func() {}, nil
}

func mustNewRuntime(t *testing.T, options RuntimeOptions) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(options)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	return runtime
}

func TestRuntimeOwnsIPsecCleanupDependencies(t *testing.T) {
	driver := &transportipsec.DryRunDriver{}
	runtime := mustNewRuntime(t, RuntimeOptions{IPsecDriver: driver, XFRMDriver: driver})
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
	prober := &closeTrackingHealthProber{}
	driver := &transportipsec.DryRunDriver{}
	runtime := mustNewRuntime(t, RuntimeOptions{IPsecDriver: driver, XFRMDriver: driver, HealthProber: prober, Close: func() error {
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
	if prober.closed != 1 {
		t.Fatalf("health prober close calls = %d, want 1", prober.closed)
	}
}

func TestRuntimeOwnsHealthProber(t *testing.T) {
	driver := &transportipsec.DryRunDriver{}
	injected := &closeTrackingHealthProber{}
	runtime := mustNewRuntime(t, RuntimeOptions{IPsecDriver: driver, XFRMDriver: driver, HealthProber: injected})
	if runtime.HealthProber() != injected {
		t.Fatal("runtime did not expose its injected health prober")
	}
	defaultRuntime := mustNewRuntime(t, RuntimeOptions{IPsecDriver: driver, XFRMDriver: driver})
	if defaultRuntime.HealthProber() == nil {
		t.Fatal("runtime did not construct the default Linux health prober")
	}
	_ = runtime.Close()
	_ = defaultRuntime.Close()
}

func TestRuntimeOwnsIPsecObservationAndLifecycleSubscription(t *testing.T) {
	driver := &lifecycleDriver{events: make(chan transportipsec.VICIEvent, 1)}
	runtime := mustNewRuntime(t, RuntimeOptions{IPsecDriver: driver, XFRMDriver: driver})
	if sas, err := runtime.ListIPsecSAs(context.Background()); err != nil || len(sas) != 0 {
		t.Fatalf("ListIPsecSAs = (%v, %v), want empty observation", sas, err)
	}
	events, stop, supported, err := runtime.SubscribeIPsecLifecycle(context.Background())
	if err != nil || !supported || events == nil || stop == nil {
		t.Fatalf("SubscribeIPsecLifecycle = (events=%v stop=%v supported=%v err=%v)", events != nil, stop != nil, supported, err)
	}
	stop()
}

func TestNewRuntimeRequiresExplicitDrivers(t *testing.T) {
	driver := &transportipsec.DryRunDriver{}
	if _, err := NewRuntime(RuntimeOptions{XFRMDriver: driver}); err == nil {
		t.Fatal("missing IPsec driver was accepted")
	}
	if _, err := NewRuntime(RuntimeOptions{IPsecDriver: driver}); err == nil {
		t.Fatal("missing XFRM driver was accepted")
	}
}
