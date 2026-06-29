package main

import (
	"fmt"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

type manualPortRotateResult struct {
	Zone               zone.ZonePath `json:"zone"`
	PreviousGeneration uint64        `json:"previous_generation,omitempty"`
	CurrentGeneration  uint64        `json:"current_generation"`
	PreviousIKE        uint16        `json:"previous_ike,omitempty"`
	PreviousNATT       uint16        `json:"previous_natt,omitempty"`
	CurrentIKE         uint16        `json:"current_ike"`
	CurrentNATT        uint16        `json:"current_natt"`
	PreviousValidUntil int64         `json:"previous_valid_until,omitempty"`
}

func debugRotatePort(direct bool) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if !direct {
		result, ok, err := rotateIPsecPortViaControl(rt)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("daemon control socket unavailable; start the daemon to trigger firewall/IPsec reconcile, or rerun with --direct to write the local DB only")
		}
		printManualPortRotateResult("daemon", result)
		return nil
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	result, err := forceLocalIPsecPortRotate(rt.Config, state, rt.Now())
	if err != nil {
		return err
	}
	if err := rt.SaveState(state); err != nil {
		return err
	}
	printManualPortRotateResult("direct", result)
	return nil
}

func printManualPortRotateResult(mode string, result *manualPortRotateResult) {
	if result == nil {
		return
	}
	fmt.Printf("mode: %s\n", mode)
	fmt.Printf("zone: %s\n", result.Zone)
	fmt.Printf("previous_generation: %d\n", result.PreviousGeneration)
	fmt.Printf("current_generation: %d\n", result.CurrentGeneration)
	if result.PreviousGeneration > 0 {
		fmt.Printf("previous_ike: %d\n", result.PreviousIKE)
		fmt.Printf("previous_natt: %d\n", result.PreviousNATT)
		fmt.Printf("previous_valid_until: %d\n", result.PreviousValidUntil)
	}
	fmt.Printf("current_ike: %d\n", result.CurrentIKE)
	fmt.Printf("current_natt: %d\n", result.CurrentNATT)
}

func forceLocalIPsecPortRotate(config *appConfig, state *stateFile, now time.Time) (*manualPortRotateResult, error) {
	if config == nil {
		config = defaultAppConfig()
	}
	if state == nil || state.Network == nil {
		return nil, fmt.Errorf("state is nil")
	}
	if state.ManagedZone == zone.RootZone || !state.ManagedZone.Valid() {
		return nil, fmt.Errorf("managed zone is required")
	}
	if len(state.ZonePrivateKey) == 0 {
		return nil, fmt.Errorf("managed zone private key is required")
	}
	mode := config.IPsec.PortMode
	if mode == "" {
		mode = ipsec.PortModeFixed
	}
	if mode != ipsec.PortModeRange {
		return nil, fmt.Errorf("manual port rotate requires ipsec.port_mode=range, got %q", mode)
	}
	if now.IsZero() {
		now = time.Now()
	}
	existing := existingIPsecPortRecord(state)
	previous := existing
	if previous == nil {
		previous = previousIPsecPortRecord(state)
	}
	prevState := ipsecPortRecordStateFromMeta(state)
	if prevState == nil {
		prevState = ipsecPortRecordStateFromRecord(existing)
	}
	nextGeneration := uint64(1)
	if prevState != nil && prevState.Generation > 0 {
		nextGeneration = prevState.Generation + 1
	}
	record, err := ipsec.PlanPortRecord(ipsec.PortPlanOptions{
		Mode:          mode,
		Range:         &config.IPsec.PortRange,
		FixedIKE:      uint16(ipsec.DefaultIKEPort),
		FixedNATT:     uint16(ipsec.DefaultNATTPort),
		Generation:    nextGeneration,
		Previous:      previous,
		PreviousGrace: config.IPsec.PortPreviousGrace,
		Now:           now,
	})
	if err != nil {
		return nil, err
	}
	changed, err := putSignedIPsecRecordIfChanged(state, state.ManagedZone, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, record, now)
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, fmt.Errorf("manual port rotate produced unchanged ipsec/ports record")
	}
	state.IPsecPortRecord = &ipsecPortRecordState{
		Mode:       record.Mode,
		Range:      record.Range,
		Generation: record.Current.Generation,
		UpdatedAt:  record.UpdatedAt,
	}
	result := &manualPortRotateResult{
		Zone:              state.ManagedZone,
		CurrentGeneration: record.Current.Generation,
		CurrentIKE:        record.Current.IKE.Advertised,
		CurrentNATT:       record.Current.NATT.Advertised,
	}
	if previous != nil && previous.Current != nil {
		result.PreviousGeneration = previous.Current.Generation
		result.PreviousIKE = previous.Current.IKE.Advertised
		result.PreviousNATT = previous.Current.NATT.Advertised
	}
	if len(record.Previous) > 0 {
		result.PreviousValidUntil = record.Previous[0].ValidUntil
	}
	return result, nil
}
