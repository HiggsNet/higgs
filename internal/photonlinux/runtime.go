package photonlinux

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	transportipsec "github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// Runtime owns the Linux platform dependencies used by Photon. It is the
// Linux composition boundary: common runtime code must not depend on netns,
// XFRM, VICI, BIRD, nftables, or other Linux implementation details.
//
// Additional Linux subsystems should share this runtime when they need common
// execution context such as a network namespace. They should not cause a
// matching set of speculative common controller interfaces to be introduced.
type Runtime struct {
	ipsecDriver       transportipsec.IPsecDriver
	xfrmDriver        transportipsec.XFRMDriver
	firewallDriver    firewall.FirewallDriver
	networkNamespaces map[string]transportipsec.NetNSSpec
	vethManager       bird.VethManager
	upstreamRoutes    UpstreamRouteManager
	birdProcess       bird.ProcessManager
	birdProcesses     map[string]bird.ProcessManager
	birdClientFactory func(string, time.Duration) BirdClient
	birdMu            sync.Mutex
	close             func() error
	logger            Logger
	closeOnce         sync.Once
	closeErr          error
}

type Logger interface {
	Debug(component, event string, fields map[string]any)
	Warn(component, event string, fields map[string]any)
}

type RuntimeOptions struct {
	IPsecDriver       transportipsec.IPsecDriver
	XFRMDriver        transportipsec.XFRMDriver
	FirewallDriver    firewall.FirewallDriver
	NetworkNamespaces map[string]transportipsec.NetNSSpec
	VethManager       bird.VethManager
	UpstreamRoutes    UpstreamRouteManager
	BirdProcess       bird.ProcessManager
	BirdProcesses     map[string]bird.ProcessManager
	BirdClientFactory func(string, time.Duration) BirdClient
	Close             func() error
	Logger            Logger
}

func NewRuntime(options RuntimeOptions) (*Runtime, error) {
	if options.IPsecDriver == nil {
		return nil, errors.New("ipsec driver is required")
	}
	if options.XFRMDriver == nil {
		return nil, errors.New("xfrm driver is required")
	}
	vethManager := options.VethManager
	if vethManager == nil {
		vethManager = bird.NewExecVethManager()
	}
	upstreamRoutes := options.UpstreamRoutes
	if upstreamRoutes == nil {
		upstreamRoutes = newExecUpstreamRouteManager()
	}
	return &Runtime{
		ipsecDriver:       options.IPsecDriver,
		xfrmDriver:        options.XFRMDriver,
		firewallDriver:    options.FirewallDriver,
		networkNamespaces: cloneNetworkNamespaces(options.NetworkNamespaces),
		vethManager:       vethManager,
		upstreamRoutes:    upstreamRoutes,
		birdProcess:       options.BirdProcess,
		birdProcesses:     cloneBirdProcesses(options.BirdProcesses),
		birdClientFactory: options.BirdClientFactory,
		close:             options.Close,
		logger:            options.Logger,
	}, nil
}

func cloneBirdProcesses(source map[string]bird.ProcessManager) map[string]bird.ProcessManager {
	if len(source) == 0 {
		return nil
	}
	cloned := make(map[string]bird.ProcessManager, len(source))
	for netns, manager := range source {
		cloned[netns] = manager
	}
	return cloned
}

func cloneNetworkNamespaces(source map[string]transportipsec.NetNSSpec) map[string]transportipsec.NetNSSpec {
	if len(source) == 0 {
		return nil
	}
	cloned := make(map[string]transportipsec.NetNSSpec, len(source))
	for alias, spec := range source {
		cloned[alias] = spec
	}
	return cloned
}

func (r *Runtime) ListIPsecSAs(ctx context.Context) ([]transportipsec.SAState, error) {
	return r.ipsecDriver.ListSAs(ctx)
}

func (r *Runtime) ApplyIPsecAction(ctx context.Context, action transportipsec.ReconcileAction, netns transportipsec.NetNSSpec) (transportipsec.ApplyPlan, error) {
	return transportipsec.ApplyReconcileAction(ctx, r.ipsecDriver, r.xfrmDriver, action, netns)
}

type ipsecLifecycleSubscriber interface {
	SubscribeLifecycleEvents(context.Context) (<-chan transportipsec.VICIEvent, func(), error)
}

func (r *Runtime) SubscribeIPsecLifecycle(ctx context.Context) (<-chan transportipsec.VICIEvent, func(), bool, error) {
	subscriber, ok := r.ipsecDriver.(ipsecLifecycleSubscriber)
	if !ok || subscriber == nil {
		return nil, nil, false, nil
	}
	events, stop, err := subscriber.SubscribeLifecycleEvents(ctx)
	return events, stop, true, err
}

// Close releases dependencies created for this runtime. Dependencies injected
// from a long-lived daemon can omit RuntimeOptions.Close and remain daemon-owned.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if r.close != nil {
			r.closeErr = r.close()
		}
	})
	return r.closeErr
}
