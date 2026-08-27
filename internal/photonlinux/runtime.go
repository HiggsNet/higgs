package photonlinux

import (
	"context"
	"sync"

	linuxipsec "github.com/HiggsNet/photon/internal/photonlinux/ipsec"
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
	closeOnce   sync.Once
	closeErr    error
}

type RuntimeOptions struct {
	IPsecDriver transportipsec.IPsecDriver
	XFRMDriver  transportipsec.XFRMDriver
	Close       func() error
}

func NewRuntime(options RuntimeOptions) *Runtime {
	return &Runtime{
		ipsecDriver: options.IPsecDriver,
		xfrmDriver:  options.XFRMDriver,
		close:       options.Close,
	}
}

// IPsecDrivers exposes the Linux transport dependencies while the existing
// daemon reconcile implementation is being moved behind Runtime. New common
// code must not depend on these Linux-facing driver types.
func (r *Runtime) IPsecDrivers() (transportipsec.IPsecDriver, transportipsec.XFRMDriver) {
	if r == nil {
		return nil, nil
	}
	return r.ipsecDriver, r.xfrmDriver
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

func (r *Runtime) CleanupIPsecLinks(ctx context.Context, instances map[string]transportipsec.LinkInstance, ids []string) (map[string]transportipsec.LinkInstance, int, error) {
	if r == nil {
		return linuxipsec.CleanupLinkInstances(ctx, instances, ids, nil, nil)
	}
	return linuxipsec.CleanupLinkInstances(ctx, instances, ids, r.ipsecDriver, r.xfrmDriver)
}

func (r *Runtime) CleanupIPsecOrphans(ctx context.Context, keep map[string]bool) (int, error) {
	if r == nil {
		return linuxipsec.CleanupOrphanConnections(ctx, keep, nil)
	}
	return linuxipsec.CleanupOrphanConnections(ctx, keep, r.ipsecDriver)
}
