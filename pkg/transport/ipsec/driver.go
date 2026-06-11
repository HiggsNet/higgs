package ipsec

import (
	"context"
	"fmt"
)

type SAState struct {
	Name           string
	Peer           string
	ChildSA        string
	XFRMIfID       uint32
	ReqID          uint32
	LocalIdentity  string
	RemoteIdentity string
	LocalEndpoint  string
	RemoteEndpoint string
	Endpoint       string
	Established    bool
}

type VICIClient interface {
	Call(context.Context, string, map[string]any) (map[string]any, error)
	CallStreaming(context.Context, string, string, map[string]any) ([]map[string]any, error)
}

type IPsecDriver interface {
	LoadConnection(context.Context, TransportLinkSpec) error
	UnloadConnection(context.Context, string) error
	TerminateSA(context.Context, string) error
	ListSAs(context.Context) ([]SAState, error)
}

type XFRMDriver interface {
	EnsureNamespace(context.Context, NetNSSpec) error
	EnsureInterface(context.Context, TransportLinkSpec) error
	DeleteInterface(context.Context, string) error
	AssignAddress(context.Context, string, string) error
}

type DryRunDriver struct {
	Connections []TransportLinkSpec
	Unloaded    []string
	Terminated  []string
	Interfaces  []TransportLinkSpec
	Namespaces  []NetNSSpec
	DeletedIFs  []string
	Addresses   []string
}

type ApplyOperation struct {
	Action string
	Target string
	Detail string
}

type ApplyPlan struct {
	Operations []ApplyOperation
}

type StrongSwanDriver struct {
	VICI VICIClient
}

func PlanApply(spec TransportLinkSpec, netns NetNSSpec) ApplyPlan {
	netns = netns.Normalized()
	plan := ApplyPlan{}
	plan.add("ensure_namespace", netns.Target(), netns.Kind)
	plan.add("load_connection", spec.TransportID, string(spec.PeerZone))
	plan.add("ensure_interface", spec.InterfaceName, fmt.Sprintf("if_id=%d netns=%s", spec.XFRMIfID, spec.NetNS))
	if spec.LocalTunnelAddr.IsValid() {
		plan.add("assign_address", spec.InterfaceName, spec.LocalTunnelAddr.String())
	}
	return plan
}

func PlanTeardown(spec TransportLinkSpec) ApplyPlan {
	plan := ApplyPlan{}
	plan.add("terminate_sa", spec.TransportID, string(spec.PeerZone))
	plan.add("unload_connection", spec.TransportID, string(spec.PeerZone))
	plan.add("delete_interface", spec.InterfaceName, fmt.Sprintf("if_id=%d netns=%s", spec.XFRMIfID, spec.NetNS))
	return plan
}

func ApplyTransportLink(ctx context.Context, ipsec IPsecDriver, xfrm XFRMDriver, spec TransportLinkSpec, netns NetNSSpec) (ApplyPlan, error) {
	if ipsec == nil {
		return ApplyPlan{}, fmt.Errorf("ipsec driver is required")
	}
	if xfrm == nil {
		return ApplyPlan{}, fmt.Errorf("xfrm driver is required")
	}
	plan := PlanApply(spec, netns)
	if err := xfrm.EnsureNamespace(ctx, netns); err != nil {
		return plan, fmt.Errorf("ensure namespace: %w", err)
	}
	if err := ipsec.LoadConnection(ctx, spec); err != nil {
		return plan, fmt.Errorf("load connection: %w", err)
	}
	if err := xfrm.EnsureInterface(ctx, spec); err != nil {
		return plan, fmt.Errorf("ensure interface: %w", err)
	}
	if spec.LocalTunnelAddr.IsValid() {
		if err := xfrm.AssignAddress(ctx, spec.InterfaceName, spec.LocalTunnelAddr.String()); err != nil {
			return plan, fmt.Errorf("assign address: %w", err)
		}
	}
	return plan, nil
}

func TeardownTransportLink(ctx context.Context, ipsec IPsecDriver, xfrm XFRMDriver, spec TransportLinkSpec) (ApplyPlan, error) {
	if ipsec == nil {
		return ApplyPlan{}, fmt.Errorf("ipsec driver is required")
	}
	if xfrm == nil {
		return ApplyPlan{}, fmt.Errorf("xfrm driver is required")
	}
	plan := PlanTeardown(spec)
	if err := ipsec.TerminateSA(ctx, spec.TransportID); err != nil {
		return plan, fmt.Errorf("terminate sa: %w", err)
	}
	if err := ipsec.UnloadConnection(ctx, spec.TransportID); err != nil {
		return plan, fmt.Errorf("unload connection: %w", err)
	}
	if err := xfrm.DeleteInterface(ctx, spec.InterfaceName); err != nil {
		return plan, fmt.Errorf("delete interface: %w", err)
	}
	return plan, nil
}

func (d StrongSwanDriver) LoadConnection(ctx context.Context, spec TransportLinkSpec) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	msg, err := BuildLoadConnMessage(spec)
	if err != nil {
		return err
	}
	_, err = d.VICI.Call(ctx, "load-conn", msg)
	return err
}

func (d StrongSwanDriver) UnloadConnection(ctx context.Context, id string) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	if id == "" {
		return fmt.Errorf("connection id is required")
	}
	_, err := d.VICI.Call(ctx, "unload-conn", map[string]any{"name": id})
	return err
}

func (d StrongSwanDriver) TerminateSA(ctx context.Context, id string) error {
	if d.VICI == nil {
		return fmt.Errorf("vici client is required")
	}
	if id == "" {
		return fmt.Errorf("sa id is required")
	}
	_, err := d.VICI.Call(ctx, "terminate", map[string]any{"ike": id, "force": "yes"})
	return err
}

func (d StrongSwanDriver) ListSAs(ctx context.Context) ([]SAState, error) {
	if d.VICI == nil {
		return nil, fmt.Errorf("vici client is required")
	}
	events, err := d.VICI.CallStreaming(ctx, "list-sas", "list-sa", nil)
	if err != nil {
		return nil, err
	}
	states := make([]SAState, 0, len(events))
	for _, event := range events {
		states = append(states, parseSAStates(event)...)
	}
	return states, nil
}

func (p *ApplyPlan) add(action, target, detail string) {
	p.Operations = append(p.Operations, ApplyOperation{Action: action, Target: target, Detail: detail})
}

func (d *DryRunDriver) LoadConnection(_ context.Context, spec TransportLinkSpec) error {
	d.Connections = append(d.Connections, spec)
	return nil
}

func (d *DryRunDriver) UnloadConnection(_ context.Context, id string) error {
	d.Unloaded = append(d.Unloaded, id)
	return nil
}

func (d *DryRunDriver) TerminateSA(_ context.Context, id string) error {
	d.Terminated = append(d.Terminated, id)
	return nil
}

func (d *DryRunDriver) ListSAs(context.Context) ([]SAState, error) {
	return nil, nil
}

func (d *DryRunDriver) EnsureNamespace(_ context.Context, spec NetNSSpec) error {
	d.Namespaces = append(d.Namespaces, spec.Normalized())
	return nil
}

func (d *DryRunDriver) EnsureInterface(_ context.Context, spec TransportLinkSpec) error {
	d.Interfaces = append(d.Interfaces, spec)
	return nil
}

func (d *DryRunDriver) DeleteInterface(_ context.Context, name string) error {
	d.DeletedIFs = append(d.DeletedIFs, name)
	return nil
}

func (d *DryRunDriver) AssignAddress(_ context.Context, name, address string) error {
	d.Addresses = append(d.Addresses, name+"="+address)
	return nil
}
