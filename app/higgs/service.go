package main

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
	higgsservice "github.com/Catofes/higgs/pkg/service"
)

const socks5RecordName = "socks5"

func publishSOCKS5Service(region, address string, port uint16, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return publishSOCKS5ServiceWithRuntime(rt, region, address, port)
}

func publishSOCKS5ServiceWithRuntime(rt *Runtime, region, address string, port uint16) error {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("invalid service address %q: %w", address, err)
	}
	value := higgsservice.SOCKS5Record{Type: higgsservice.TypeSOCKS5, Region: region, Address: addr.String(), Port: port}
	if err := value.Validate(); err != nil {
		return err
	}
	return submitSOCKS5ServiceRecord(rt, value, "published")
}

func withdrawSOCKS5Service(direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return withdrawSOCKS5ServiceWithRuntime(rt)
}

func withdrawSOCKS5ServiceWithRuntime(rt *Runtime) error {
	key, _ := higgsservice.RecordKey(socks5RecordName)
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	zs := state.Network.Zones[state.ManagedZone]
	if zs == nil || zs.Records[key] == nil {
		return fmt.Errorf("service %q is not published", socks5RecordName)
	}
	current, err := higgsservice.ParseSOCKS5Record(zs.Records[key])
	if err != nil {
		return fmt.Errorf("current service record is invalid: %w", err)
	}
	if !current.IsActive() {
		return fmt.Errorf("service %q is already withdrawn", socks5RecordName)
	}
	active := false
	current.Active = &active
	return submitSOCKS5ServiceRecord(rt, *current, "withdrew")
}

func submitSOCKS5ServiceRecord(rt *Runtime, value higgsservice.SOCKS5Record, operation string) error {
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	key, err := higgsservice.RecordKey(socks5RecordName)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal service record: %w", err)
	}
	candidate := &zone.Record{Zone: state.ManagedZone, Key: key, Type: higgsservice.RecordTypeSOCKS5, Value: encoded}
	if value.IsActive() {
		ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
		if err != nil {
			return fmt.Errorf("build route authorization: %w", err)
		}
		if _, err := higgsservice.AuthorizeSOCKS5Record(candidate, ars); err != nil {
			return err
		}
	}
	if version, ok, err := putRecordViaControl(rt, state.ManagedZone, key, encoded, higgsservice.RecordTypeSOCKS5); ok {
		if err != nil {
			return err
		}
		fmt.Printf("%s service %s version %d via daemon\n", operation, socks5RecordName, version)
		return nil
	}
	if !rt.DisableControl {
		logControlFallback("service_submit")
	}
	if err := putRecordDirect(rt, state.ManagedZone, key, encoded, higgsservice.RecordTypeSOCKS5); err != nil {
		return err
	}
	return nil
}
