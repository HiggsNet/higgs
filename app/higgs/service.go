package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
	"github.com/Catofes/higgs/pkg/routing"
	higgsservice "github.com/Catofes/higgs/pkg/service"
)

type serviceValidationReport struct {
	ManagedZone string                 `json:"managed_zone"`
	Services    []serviceValidationRow `json:"services"`
}

type serviceValidationRow struct {
	ID               string   `json:"id"`
	Type             string   `json:"type"`
	Region           string   `json:"region"`
	NetNS            string   `json:"netns"`
	Address          string   `json:"address"`
	Port             uint16   `json:"port"`
	AllowZones       []string `json:"allow_zones"`
	RecordKey        string   `json:"record_key"`
	RecordType       string   `json:"record_type"`
	AssignmentPrefix string   `json:"assignment_prefix"`
}

func validateServices(filterID string, jsonOutput bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	report, err := buildServiceValidationReport(rt, state, filterID)
	if err != nil {
		return err
	}
	if jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	fmt.Fprintf(os.Stdout, "managed_zone: %s\n", report.ManagedZone)
	fmt.Fprintf(os.Stdout, "services: %d\n", len(report.Services))
	for _, row := range report.Services {
		endpoint := netip.AddrPortFrom(netip.MustParseAddr(row.Address), row.Port)
		fmt.Fprintf(os.Stdout, "  %s  %s://%s  region=%s  netns=%s  assignment=%s\n",
			row.ID, row.Type, endpoint, row.Region, row.NetNS, row.AssignmentPrefix)
	}
	return nil
}

func buildServiceValidationReport(rt *Runtime, state *stateFile, filterID string) (*serviceValidationReport, error) {
	if rt == nil || rt.Config == nil {
		return nil, fmt.Errorf("runtime config is nil")
	}
	if state == nil || state.Network == nil {
		return nil, fmt.Errorf("state is nil")
	}
	filterID = strings.TrimSpace(filterID)
	if filterID != "" {
		var err error
		filterID, err = higgsservice.NormalizeID(filterID)
		if err != nil {
			return nil, err
		}
	}
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		return nil, fmt.Errorf("build route authorization: %w", err)
	}
	report := &serviceValidationReport{
		ManagedZone: state.ManagedZone.String(),
		Services:    []serviceValidationRow{},
	}
	found := false
	for _, configured := range rt.Config.Services {
		if filterID != "" && configured.ID != filterID {
			continue
		}
		found = true
		record, err := buildConfiguredServiceRecord(state, configured, rt.Now())
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", configured.ID, err)
		}
		zs := state.Network.Zones[state.ManagedZone]
		if zs == nil || zs.Authority == nil {
			return nil, fmt.Errorf("service %s: %w: %s", configured.ID, zone.ErrZoneNotFound, state.ManagedZone)
		}
		if err := higgscrypto.VerifyRecord(record, zs.Authority, rt.Now()); err != nil {
			return nil, fmt.Errorf("service %s write authorization: %w", configured.ID, err)
		}
		assignment, err := higgsservice.AuthorizeSOCKS5Record(record, ars)
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", configured.ID, err)
		}
		allowZones := make([]string, 0, len(configured.AllowZones))
		for _, path := range configured.AllowZones {
			allowZones = append(allowZones, path.String())
		}
		report.Services = append(report.Services, serviceValidationRow{
			ID:               configured.ID,
			Type:             configured.Type,
			Region:           configured.Region,
			NetNS:            configured.NetNS,
			Address:          configured.Address.String(),
			Port:             configured.Port,
			AllowZones:       allowZones,
			RecordKey:        record.Key,
			RecordType:       record.Type,
			AssignmentPrefix: assignment.Prefix.String(),
		})
	}
	if filterID != "" && !found {
		return nil, fmt.Errorf("service %q is not configured", filterID)
	}
	return report, nil
}

func buildConfiguredServiceRecord(state *stateFile, configured serviceConfig, now time.Time) (*zone.Record, error) {
	key, err := higgsservice.RecordKey(configured.ID)
	if err != nil {
		return nil, err
	}
	value, err := json.Marshal(higgsservice.SOCKS5Record{
		Type:    configured.Type,
		Region:  configured.Region,
		Address: configured.Address.String(),
		Port:    configured.Port,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal service record: %w", err)
	}
	return buildSignedRecordAt(state, state.ManagedZone, key, value, higgsservice.RecordTypeSOCKS5, now)
}
