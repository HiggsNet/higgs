package ipsec

import "context"

type SAState struct {
	Name        string
	Peer        string
	ChildSA     string
	XFRMIfID    uint32
	Endpoint    string
	Established bool
}

type IPsecDriver interface {
	LoadConnection(context.Context, TransportLinkSpec) error
	UnloadConnection(context.Context, string) error
	TerminateSA(context.Context, string) error
	ListSAs(context.Context) ([]SAState, error)
}

type XFRMDriver interface {
	EnsureInterface(context.Context, TransportLinkSpec) error
	DeleteInterface(context.Context, string) error
	AssignAddress(context.Context, string, string) error
}

type DryRunDriver struct {
	Connections []TransportLinkSpec
	Unloaded    []string
	Terminated  []string
	Interfaces  []TransportLinkSpec
	DeletedIFs  []string
	Addresses   []string
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
