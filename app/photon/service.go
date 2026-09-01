package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	photonservice "github.com/HiggsNet/photon/pkg/service"
)

const socks5RecordName = "socks5"

func showServices(filter string, includeAll, localOnly, verbose bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.ServiceInspection](rt, controlRequest{Method: "services_view"}); err != nil {
		return err
	} else if ok {
		return inspecttext.WriteServices(os.Stdout, view, filter, includeAll, localOnly, verbose)
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil {
		return errors.New("common state is not initialized")
	}
	view := inspect.BuildServiceInspection(common.State, rt.Now())
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
	intent, err := commonServiceIntent(request)
	if err != nil {
		return err
	}
	result, err := applyOfflineCommonIntent(rt, intent, request.DryRun)
	if err != nil {
		return err
	}
	if result.Record == nil {
		return errors.New("service mutation did not return a record")
	}
	fmt.Printf("%s service %s version %d\n", operation, socks5RecordName, result.Record.Version)
	return nil
}
