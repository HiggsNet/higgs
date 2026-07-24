package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/routing"
	higgsservice "github.com/Catofes/higgs/pkg/service"
)

const socks5RecordName = "socks5"

func publishSOCKS5Endpoints(endpoints []higgsservice.SOCKS5Endpoint, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return publishSOCKS5EndpointsWithRuntime(rt, endpoints)
}

func publishSOCKS5EndpointsWithRuntime(rt *Runtime, endpoints []higgsservice.SOCKS5Endpoint) error {
	canonical := make([]higgsservice.SOCKS5Endpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		addr, err := netip.ParseAddr(endpoint.Address)
		if err != nil {
			return fmt.Errorf("invalid service address %q: %w", endpoint.Address, err)
		}
		endpoint.Address = addr.String()
		canonical = append(canonical, endpoint)
	}
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].Region != canonical[j].Region {
			return canonical[i].Region < canonical[j].Region
		}
		return canonical[i].Address < canonical[j].Address
	})
	value := higgsservice.SOCKS5Record{Type: higgsservice.TypeSOCKS5, Endpoints: canonical}
	if err := value.Validate(); err != nil {
		return err
	}
	return submitSOCKS5ServiceRecord(rt, value, "published")
}

func parseSOCKS5EndpointFlags(values []string, legacyRegion, legacyAddress string, legacyPort uint16) ([]higgsservice.SOCKS5Endpoint, error) {
	if len(values) == 0 {
		if legacyRegion == "" || legacyAddress == "" {
			return nil, fmt.Errorf("at least one --endpoint is required")
		}
		return []higgsservice.SOCKS5Endpoint{{Region: legacyRegion, Address: legacyAddress, Port: legacyPort}}, nil
	}
	if legacyRegion != "" || legacyAddress != "" {
		return nil, fmt.Errorf("--endpoint cannot be combined with --region or --address")
	}
	endpoints := make([]higgsservice.SOCKS5Endpoint, 0, len(values))
	for _, value := range values {
		parts := strings.Split(value, ",")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid endpoint %q: expected region,address,port", value)
		}
		port, err := strconv.ParseUint(parts[2], 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("invalid endpoint port in %q", value)
		}
		endpoints = append(endpoints, higgsservice.SOCKS5Endpoint{Region: parts[0], Address: parts[1], Port: uint16(port)})
	}
	return endpoints, nil
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
		return nil
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
