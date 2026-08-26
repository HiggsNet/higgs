package main

import (
	"fmt"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	photonservice "github.com/HiggsNet/photon/pkg/service"
)

// commonIPAMIntent is the thin control-adapter boundary. It translates the
// wire request into one explicit public Store intent and performs no state
// reads or semantic validation of its own.
func commonIPAMIntent(request ipamMutationRequest) (corestate.LocalIntent, error) {
	switch request.Operation {
	case ipamOperationPoolCreate:
		return corestate.PutIPAMPoolIntent{
			Zone: request.Zone, Prefix: request.Prefix, DelegatedTo: request.Target,
		}, nil
	case ipamOperationPoolRevoke:
		return corestate.RevokeIPAMPoolIntent{Zone: request.Zone, Prefix: request.Prefix}, nil
	case ipamOperationAssignmentCreate:
		return corestate.PutIPAMAssignmentIntent{
			Zone: request.Zone, Prefix: request.Prefix, AssignedTo: request.Target, Shared: request.Shared, Tag: request.Tag,
		}, nil
	case ipamOperationAssignmentRevoke:
		return corestate.RevokeIPAMAssignmentIntent{
			Zone: request.Zone, Prefix: request.Prefix, AssignedTo: request.Target,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported IPAM operation %q", request.Operation)
	}
}

func commonRouteIntent(request routeMutationRequest) corestate.LocalIntent {
	if request.Active {
		return corestate.AnnounceRouteIntent{Zone: request.Zone, Prefix: request.Prefix}
	}
	return corestate.WithdrawRouteIntent{Zone: request.Zone, Prefix: request.Prefix}
}

func commonServiceIntent(request serviceMutationRequest) (corestate.LocalIntent, error) {
	switch request.Operation {
	case serviceOperationPublish:
		return corestate.PublishSOCKS5Intent{Endpoints: append([]photonservice.SOCKS5Endpoint(nil), request.Endpoints...)}, nil
	case serviceOperationWithdraw:
		return corestate.WithdrawSOCKS5Intent{}, nil
	default:
		return nil, fmt.Errorf("unsupported service operation %q", request.Operation)
	}
}
