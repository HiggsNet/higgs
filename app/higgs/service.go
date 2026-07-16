package main

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
	higgsservice "github.com/Catofes/higgs/pkg/service"
)

func publishSOCKS5Service(name, region, address string, port uint16, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return publishSOCKS5ServiceWithRuntime(rt, name, region, address, port)
}

func publishSOCKS5ServiceWithRuntime(rt *Runtime, name, region, address string, port uint16) error {
	id, err := higgsservice.NormalizeID(name)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("invalid service address %q: %w", address, err)
	}
	value := higgsservice.SOCKS5Record{Type: higgsservice.TypeSOCKS5, Region: region, Address: addr.String(), Port: port}
	if err := value.Validate(); err != nil {
		return err
	}
	return submitSOCKS5ServiceRecord(rt, id, value, "published")
}

func withdrawSOCKS5Service(name string, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return withdrawSOCKS5ServiceWithRuntime(rt, name)
}

func withdrawSOCKS5ServiceWithRuntime(rt *Runtime, name string) error {
	id, err := higgsservice.NormalizeID(name)
	if err != nil {
		return err
	}
	key, _ := higgsservice.RecordKey(id)
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	zs := state.Network.Zones[state.ManagedZone]
	if zs == nil || zs.Records[key] == nil {
		return fmt.Errorf("service %q is not published", id)
	}
	current, err := higgsservice.ParseSOCKS5Record(zs.Records[key])
	if err != nil {
		return fmt.Errorf("current service record is invalid: %w", err)
	}
	if !current.IsActive() {
		return fmt.Errorf("service %q is already withdrawn", id)
	}
	active := false
	current.Active = &active
	return submitSOCKS5ServiceRecord(rt, id, *current, "withdrew")
}

func submitSOCKS5ServiceRecord(rt *Runtime, id string, value higgsservice.SOCKS5Record, operation string) error {
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	key, err := higgsservice.RecordKey(id)
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
		fmt.Printf("%s service %s version %d via daemon\n", operation, id, version)
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
