package photonlinux

import (
	"context"
	"errors"
	"sync"

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
	ipsecDriver transportipsec.IPsecDriver
	xfrmDriver  transportipsec.XFRMDriver
	close       func() error
	logger      Logger
	closeOnce   sync.Once
	closeErr    error
}

type Logger interface {
	Debug(component, event string, fields map[string]any)
	Warn(component, event string, fields map[string]any)
}

type RuntimeOptions struct {
	IPsecDriver transportipsec.IPsecDriver
	XFRMDriver  transportipsec.XFRMDriver
	Close       func() error
	Logger      Logger
}

func NewRuntime(options RuntimeOptions) (*Runtime, error) {
	if options.IPsecDriver == nil {
		return nil, errors.New("ipsec driver is required")
	}
	if options.XFRMDriver == nil {
		return nil, errors.New("xfrm driver is required")
	}
	return &Runtime{
		ipsecDriver: options.IPsecDriver,
		xfrmDriver:  options.XFRMDriver,
		close:       options.Close,
		logger:      options.Logger,
	}, nil
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
