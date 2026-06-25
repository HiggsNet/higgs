package ipsec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type CommandRunner func(context.Context, string, ...string) ([]byte, error)

type SystemXFRMDriver struct {
	Command      CommandRunner
	Stat         func(string) error
	DefaultNetNS NetNSSpec
	StateNetNS   NetNSSpec
}

func NewSystemXFRMDriver(defaultNetNS NetNSSpec) SystemXFRMDriver {
	return SystemXFRMDriver{
		Command:      execCommand,
		Stat:         statPath,
		DefaultNetNS: defaultNetNS.Normalized(),
		StateNetNS:   NetNSSpec{Kind: NetNSHost},
	}
}

func (d SystemXFRMDriver) EnsureNamespace(ctx context.Context, spec NetNSSpec) error {
	spec = spec.Normalized()
	if err := spec.Validate(); err != nil {
		return err
	}
	switch spec.Kind {
	case NetNSHost:
		return nil
	case NetNSPath:
		stat := d.Stat
		if stat == nil {
			stat = statPath
		}
		if err := stat(spec.Path); err != nil {
			return fmt.Errorf("netns path %s: %w", spec.Path, err)
		}
		return nil
	case NetNSName:
		if d.netnsExists(ctx, spec.Name) {
			return nil
		}
		if !spec.Create {
			return fmt.Errorf("netns %q does not exist and create=false", spec.Name)
		}
		if err := d.run(ctx, "ip", "netns", "add", spec.Name); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported netns kind %q", spec.Kind)
	}
}

func (d SystemXFRMDriver) EnsureInterface(ctx context.Context, spec TransportLinkSpec) error {
	if spec.InterfaceName == "" {
		return errors.New("interface name is required")
	}
	if spec.XFRMIfID == 0 {
		return errors.New("xfrm if_id is required")
	}
	netns, err := d.specNetNS(spec)
	if err != nil {
		return err
	}
	if err := d.EnsureNamespace(ctx, netns); err != nil {
		return err
	}
	if d.linkExists(ctx, netns, spec.InterfaceName) {
		return d.setLinkUp(ctx, netns, spec.InterfaceName)
	}
	stateNetNS := d.stateNetNS()
	if d.linkExists(ctx, stateNetNS, spec.InterfaceName) {
		if err := d.moveLinkFrom(ctx, stateNetNS, spec.InterfaceName, netns); err != nil {
			return err
		}
		return d.setLinkUp(ctx, netns, spec.InterfaceName)
	}
	if err := d.addXFRMInterface(ctx, stateNetNS, spec.InterfaceName, spec.XFRMIfID); err != nil {
		return err
	}
	if err := d.moveLinkFrom(ctx, stateNetNS, spec.InterfaceName, netns); err != nil {
		return err
	}
	return d.setLinkUp(ctx, netns, spec.InterfaceName)
}

func (d SystemXFRMDriver) DeleteInterface(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("interface name is required")
	}
	netns := d.DefaultNetNS.Normalized()
	if d.linkExists(ctx, netns, name) {
		return d.runInNetNS(ctx, netns, "link", "delete", name)
	}
	if d.linkExists(ctx, NetNSSpec{Kind: NetNSHost}, name) {
		return d.run(ctx, "ip", "link", "delete", name)
	}
	return nil
}

func (d SystemXFRMDriver) AssignAddress(ctx context.Context, name, address string) error {
	if name == "" {
		return errors.New("interface name is required")
	}
	if address == "" {
		return errors.New("address is required")
	}
	netns := d.DefaultNetNS.Normalized()
	return d.runInNetNS(ctx, netns, "addr", "replace", address, "dev", name)
}

func (d SystemXFRMDriver) specNetNS(spec TransportLinkSpec) (NetNSSpec, error) {
	defaultNS := d.DefaultNetNS.Normalized()
	if spec.NetNS == "" {
		return defaultNS, defaultNS.Validate()
	}
	if defaultNS.Kind == NetNSName && spec.NetNS == defaultNS.Name {
		return defaultNS, defaultNS.Validate()
	}
	ns := NetNSSpec{Kind: NetNSName, Name: spec.NetNS}
	if strings.HasPrefix(spec.NetNS, "/") {
		ns = NetNSSpec{Kind: NetNSPath, Path: spec.NetNS}
	}
	return ns.Normalized(), ns.Validate()
}

func (d SystemXFRMDriver) stateNetNS() NetNSSpec {
	if d.StateNetNS.Kind == "" && d.StateNetNS.Name == "" && d.StateNetNS.Path == "" {
		return NetNSSpec{Kind: NetNSHost}
	}
	return d.StateNetNS.Normalized()
}

func (d SystemXFRMDriver) netnsExists(ctx context.Context, name string) bool {
	return d.commandSucceeds(ctx, "ip", "netns", "exec", name, "true")
}

func (d SystemXFRMDriver) linkExists(ctx context.Context, netns NetNSSpec, name string) bool {
	if netns.Normalized().Kind == NetNSHost {
		return d.commandSucceeds(ctx, "ip", "link", "show", "dev", name)
	}
	return d.commandSucceedsInNetNS(ctx, netns, "link", "show", "dev", name)
}

func (d SystemXFRMDriver) moveLinkFrom(ctx context.Context, source NetNSSpec, name string, target NetNSSpec) error {
	source = source.Normalized()
	target = target.Normalized()
	if sameNetNS(source, target) {
		return nil
	}
	switch source.Kind {
	case NetNSHost:
		return d.moveLink(ctx, name, target)
	case NetNSName:
		switch target.Kind {
		case NetNSHost:
			return d.runInNetNS(ctx, source, "link", "set", name, "netns", "1")
		case NetNSName:
			return d.runInNetNS(ctx, source, "link", "set", name, "netns", target.Name)
		case NetNSPath:
			return fmt.Errorf("moving links to path netns %q is not supported by the exec driver; bind it under /var/run/netns and use kind=name", target.Path)
		default:
			return fmt.Errorf("unsupported netns kind %q", target.Kind)
		}
	case NetNSPath:
		return fmt.Errorf("moving links from path netns %q is not supported by the exec driver; bind it under /var/run/netns and use kind=name", source.Path)
	default:
		return fmt.Errorf("unsupported netns kind %q", source.Kind)
	}
}

func (d SystemXFRMDriver) moveLink(ctx context.Context, name string, netns NetNSSpec) error {
	netns = netns.Normalized()
	switch netns.Kind {
	case NetNSHost:
		return nil
	case NetNSName:
		return d.run(ctx, "ip", "link", "set", name, "netns", netns.Name)
	case NetNSPath:
		return fmt.Errorf("moving links to path netns %q is not supported by the exec driver; bind it under /var/run/netns and use kind=name", netns.Path)
	default:
		return fmt.Errorf("unsupported netns kind %q", netns.Kind)
	}
}

func sameNetNS(a, b NetNSSpec) bool {
	a = a.Normalized()
	b = b.Normalized()
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case NetNSHost:
		return true
	case NetNSName:
		return a.Name == b.Name
	case NetNSPath:
		return a.Path == b.Path
	default:
		return false
	}
}

func (d SystemXFRMDriver) addXFRMInterface(ctx context.Context, netns NetNSSpec, name string, ifID uint32) error {
	args := []string{"link", "add", name, "type", "xfrm", "if_id", fmt.Sprintf("%d", ifID)}
	return d.runInNetNS(ctx, netns, args...)
}

func (d SystemXFRMDriver) setLinkUp(ctx context.Context, netns NetNSSpec, name string) error {
	return d.runInNetNS(ctx, netns, "link", "set", "dev", name, "up")
}

func (d SystemXFRMDriver) runInNetNS(ctx context.Context, netns NetNSSpec, args ...string) error {
	netns = netns.Normalized()
	if netns.Kind == NetNSHost {
		return d.run(ctx, "ip", args...)
	}
	if netns.Kind == NetNSPath {
		return fmt.Errorf("path netns %q is not supported by the exec driver; bind it under /var/run/netns and use kind=name", netns.Path)
	}
	full := append([]string{"netns", "exec", netns.Name, "ip"}, args...)
	return d.run(ctx, "ip", full...)
}

func (d SystemXFRMDriver) commandSucceedsInNetNS(ctx context.Context, netns NetNSSpec, args ...string) bool {
	netns = netns.Normalized()
	if netns.Kind == NetNSHost {
		return d.commandSucceeds(ctx, "ip", args...)
	}
	if netns.Kind == NetNSPath {
		return false
	}
	full := append([]string{"netns", "exec", netns.Name, "ip"}, args...)
	return d.commandSucceeds(ctx, "ip", full...)
}

func (d SystemXFRMDriver) commandSucceeds(ctx context.Context, name string, args ...string) bool {
	return d.run(ctx, name, args...) == nil
}

func (d SystemXFRMDriver) run(ctx context.Context, name string, args ...string) error {
	runner := d.Command
	if runner == nil {
		runner = execCommand
	}
	out, err := runner(ctx, name, args...)
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, detail)
	}
	return nil
}

func execCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func statPath(path string) error {
	_, err := os.Stat(path)
	return err
}
