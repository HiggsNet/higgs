package text

import (
	"fmt"
	"io"
	"net"
	"strings"
	"text/tabwriter"

	"github.com/Catofes/higgs/internal/inspect"
)

func WriteServices(w io.Writer, view inspect.ServiceInspection, filter string, includeAll, localOnly, verbose bool) error {
	filter = strings.ToLower(strings.TrimSpace(filter))
	services := make([]inspect.ServiceView, 0, len(view.Services))
	eligibleCount := 0
	for _, service := range view.Services {
		if localOnly && !service.Local {
			continue
		}
		if !includeAll && service.Status == "withdrawn" {
			continue
		}
		eligibleCount++
		searchable := []string{
			service.ID,
			service.Type,
			string(service.Owner),
			service.Status,
			service.RecordKey,
			service.Error,
		}
		for _, endpoint := range service.Endpoints {
			searchable = append(searchable, endpoint.Region, endpoint.Address, fmt.Sprint(endpoint.Port))
		}
		if filter == "" || strings.Contains(strings.ToLower(strings.Join(searchable, " ")), filter) {
			services = append(services, service)
		}
	}

	endpointCount := 0
	for _, service := range services {
		endpointCount += max(1, len(service.Endpoints))
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	out := newLineWriter(table)
	out.Linef("managed_zone: %s", dash(string(view.ManagedZone)))
	out.Linef("services: %s", filteredCount(len(services), eligibleCount, filter))
	out.Linef("endpoints: %d", endpointCount)
	if verbose {
		out.Println("SERVICE\tTYPE\tOWNER\tSCOPE\tREGION\tENDPOINT\tSTATUS\tVERSION\tUPDATED\tRECORD\tERROR")
	} else {
		out.Println("SERVICE\tTYPE\tOWNER\tSCOPE\tREGION\tENDPOINT\tSTATUS")
	}
	for _, service := range services {
		endpoints := service.Endpoints
		if len(endpoints) == 0 {
			endpoints = []inspect.ServiceEndpointView{{}}
		}
		for _, endpoint := range endpoints {
			scope := "remote"
			if service.Local {
				scope = "local"
			}
			address := "-"
			if endpoint.Address != "" && endpoint.Port != 0 {
				address = net.JoinHostPort(endpoint.Address, fmt.Sprint(endpoint.Port))
			}
			if verbose {
				out.Linef("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s",
					service.ID,
					dash(service.Type),
					service.Owner,
					scope,
					dash(endpoint.Region),
					address,
					dash(service.Status),
					service.Version,
					formatUnixTime(service.UpdatedUnix),
					dash(service.RecordKey),
					escapeTableCell(dash(service.Error)),
				)
			} else {
				out.Linef("%s\t%s\t%s\t%s\t%s\t%s\t%s",
					service.ID,
					dash(service.Type),
					service.Owner,
					scope,
					dash(endpoint.Region),
					address,
					dash(service.Status),
				)
			}
		}
	}
	if err := out.Err(); err != nil {
		return err
	}
	return table.Flush()
}
