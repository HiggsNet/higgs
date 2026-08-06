package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Catofes/photon/internal/inspect"
	inspecttext "github.com/Catofes/photon/internal/inspect/text"
	"github.com/Catofes/photon/pkg/core/zone"
	"github.com/Catofes/photon/pkg/routing"
	photonservice "github.com/Catofes/photon/pkg/service"
)

const socks5RecordName = "socks5"

func showServices(filter string, includeAll, localOnly, verbose bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	view := inspect.BuildServiceInspection(inspect.ServiceInspectionInput{
		Network:     state.Network,
		ManagedZone: state.ManagedZone,
		Now:         rt.Now(),
	})
	return inspecttext.WriteServices(os.Stdout, view, filter, includeAll, localOnly, verbose)
}

type serviceMutationRequest struct {
	Operation string                         `json:"operation"`
	Endpoints []photonservice.SOCKS5Endpoint `json:"endpoints,omitempty"`
	DryRun    bool                           `json:"dry_run,omitempty"`
}

const (
	serviceOperationPublish  = "publish"
	serviceOperationWithdraw = "withdraw"
)

func publishSOCKS5Endpoints(endpoints []photonservice.SOCKS5Endpoint, direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	rt.DisableControl = direct
	return publishSOCKS5EndpointsWithRuntime(rt, endpoints)
}

func publishSOCKS5EndpointsWithRuntime(rt *Runtime, endpoints []photonservice.SOCKS5Endpoint) error {
	return submitServiceMutation(rt, serviceMutationRequest{
		Operation: serviceOperationPublish,
		Endpoints: append([]photonservice.SOCKS5Endpoint(nil), endpoints...),
	}, "published")
}

func parseSOCKS5EndpointFlags(values []string, legacyRegion, legacyAddress string, legacyPort uint16) ([]photonservice.SOCKS5Endpoint, error) {
	if len(values) == 0 {
		if legacyRegion == "" || legacyAddress == "" {
			return nil, fmt.Errorf("at least one --endpoint is required")
		}
		return []photonservice.SOCKS5Endpoint{{Region: legacyRegion, Address: legacyAddress, Port: legacyPort}}, nil
	}
	if legacyRegion != "" || legacyAddress != "" {
		return nil, fmt.Errorf("--endpoint cannot be combined with --region or --address")
	}
	endpoints := make([]photonservice.SOCKS5Endpoint, 0, len(values))
	for _, value := range values {
		parts := strings.Split(value, ",")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid endpoint %q: expected region,address,port", value)
		}
		port, err := strconv.ParseUint(parts[2], 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("invalid endpoint port in %q", value)
		}
		endpoints = append(endpoints, photonservice.SOCKS5Endpoint{Region: parts[0], Address: parts[1], Port: uint16(port)})
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
	return submitServiceMutation(rt, serviceMutationRequest{Operation: serviceOperationWithdraw}, "withdrew")
}

func submitServiceMutation(rt *Runtime, request serviceMutationRequest, operation string) error {
	if version, ok, err := mutateServiceViaControl(rt, request); ok {
		if err != nil {
			return err
		}
		fmt.Printf("%s service %s version %d via daemon\n", operation, socks5RecordName, version)
		return nil
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	result, err := applyServiceMutation(state, request, rt.Now())
	if err != nil {
		return err
	}
	if !result.DryRun {
		if err := rt.SaveState(state); err != nil {
			return err
		}
	}
	fmt.Printf("%s service %s version %d\n", operation, socks5RecordName, result.Version)
	return nil
}

func applyServiceMutation(state *stateFile, request serviceMutationRequest, now time.Time) (*recordMutationResult, error) {
	if state == nil || state.Network == nil {
		return nil, errors.New("state is nil")
	}
	path := state.ManagedZone
	if !path.Valid() {
		return nil, fmt.Errorf("invalid managed zone: %s", path)
	}
	key, err := photonservice.RecordKey(socks5RecordName)
	if err != nil {
		return nil, err
	}
	var value photonservice.SOCKS5Record
	switch request.Operation {
	case serviceOperationPublish:
		canonical := make([]photonservice.SOCKS5Endpoint, 0, len(request.Endpoints))
		for _, endpoint := range request.Endpoints {
			addr, err := netip.ParseAddr(endpoint.Address)
			if err != nil {
				return nil, fmt.Errorf("invalid service address %q: %w", endpoint.Address, err)
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
		value = photonservice.SOCKS5Record{Type: photonservice.TypeSOCKS5, Endpoints: canonical}
		if err := value.Validate(); err != nil {
			return nil, err
		}
	case serviceOperationWithdraw:
		zs := state.Network.Zones[path]
		if zs == nil || zs.Records[key] == nil {
			return nil, fmt.Errorf("service %q is not published", socks5RecordName)
		}
		current, err := photonservice.ParseSOCKS5Record(zs.Records[key])
		if err != nil {
			return nil, fmt.Errorf("current service record is invalid: %w", err)
		}
		if !current.IsActive() {
			return nil, fmt.Errorf("service %q is already withdrawn", socks5RecordName)
		}
		active := false
		current.Active = &active
		value = *current
	default:
		return nil, fmt.Errorf("unsupported service operation %q", request.Operation)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal service record: %w", err)
	}
	if value.IsActive() {
		candidate := &zone.Record{Zone: path, Key: key, Type: photonservice.RecordTypeSOCKS5, Value: encoded}
		ars, err := routing.BuildAuthorizedRouteSet(state.Network, now)
		if err != nil {
			return nil, fmt.Errorf("build route authorization: %w", err)
		}
		if _, err := photonservice.AuthorizeSOCKS5Record(candidate, ars); err != nil {
			return nil, err
		}
	}
	record, err := buildSignedRecordAt(state, path, key, encoded, photonservice.RecordTypeSOCKS5, now)
	if err != nil {
		return nil, err
	}
	result := &recordMutationResult{Zone: path, Key: key, Version: record.Version, DryRun: request.DryRun}
	if request.DryRun {
		return result, nil
	}
	if err := state.Network.Put(record); err != nil {
		return nil, err
	}
	return result, nil
}
