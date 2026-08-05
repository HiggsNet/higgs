package inspect

import (
	"sort"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgsservice "github.com/Catofes/higgs/pkg/service"
)

type ServiceInspectionInput struct {
	Network     *zone.NetworkState
	ManagedZone zone.ZonePath
	Now         time.Time
}

type ServiceInspection struct {
	ManagedZone zone.ZonePath
	Services    []ServiceView
}

type ServiceView struct {
	ID          string
	Type        string
	Owner       zone.ZonePath
	Local       bool
	Active      bool
	Status      string
	Endpoints   []ServiceEndpointView
	Version     uint64
	UpdatedUnix int64
	RecordKey   string
	Error       string
}

type ServiceEndpointView struct {
	Region  string
	Address string
	Port    uint16
}

func BuildServiceInspection(input ServiceInspectionInput) ServiceInspection {
	view := ServiceInspection{ManagedZone: input.ManagedZone}
	if input.Network == nil {
		return view
	}

	paths := make([]zone.ZonePath, 0, len(input.Network.Zones))
	for path := range input.Network.Zones {
		paths = append(paths, path)
	}
	SortZonePaths(paths)
	for _, path := range paths {
		if input.Network.IsZoneRevoked(path, input.Now) {
			continue
		}
		state := input.Network.Zones[path]
		if state == nil {
			continue
		}
		keys := make([]string, 0, len(state.Records))
		for key := range state.Records {
			if strings.HasPrefix(key, higgsservice.RecordKeyPrefix) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			record := state.Records[key]
			if record == nil || record.Type != higgsservice.RecordTypeSOCKS5 {
				continue
			}
			serviceView := ServiceView{
				ID:          strings.TrimPrefix(key, higgsservice.RecordKeyPrefix),
				Type:        higgsservice.TypeSOCKS5,
				Owner:       path,
				Local:       path == input.ManagedZone,
				Version:     record.Version,
				UpdatedUnix: record.Timestamp,
				RecordKey:   record.Key,
			}
			value, err := higgsservice.ParseSOCKS5Record(record)
			if err != nil {
				serviceView.Status = "invalid"
				serviceView.Error = err.Error()
				view.Services = append(view.Services, serviceView)
				continue
			}
			serviceView.Active = value.IsActive()
			serviceView.Status = "withdrawn"
			if serviceView.Active {
				serviceView.Status = "active"
			}
			for _, endpoint := range value.EffectiveEndpoints() {
				serviceView.Endpoints = append(serviceView.Endpoints, ServiceEndpointView{
					Region:  endpoint.Region,
					Address: endpoint.Address,
					Port:    endpoint.Port,
				})
			}
			view.Services = append(view.Services, serviceView)
		}
	}
	return view
}
