package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
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
	result, err := rotateIPsecPortDirect(rt)
	if err != nil {
		return err
	}
	printManualPortRotateResult("direct", result)
	return nil
}

func debugRotate(ctx context.Context, filter string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if response, ok, err := linksStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		if response.Links == nil {
			return errors.New("daemon links_status response missing links")
		}
		fmt.Printf("daemon: online peer_id=%s link_instances=%d desired_links=%d last_link_error=%s\n",
			response.PeerID,
			response.Links.Inspection.Summary.LinkInstances,
			response.Links.Inspection.Summary.DesiredLinks,
			dash(response.Links.Inspection.Summary.LastError),
		)
		build := linkInspectionBuildFromControl(response.Links)
		storedSAs := append([]linkSAState(nil), response.Links.ActualSAs...)
		return writeDebugRotateFromBuild(os.Stdout, build, filter, storedSAs, nil, nil, "daemon_sas", "direct_live_sas")
	}
	common, runtime, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	var liveSAs []linkSAState
	var liveErr error
	if rt.Config != nil && rt.Config.IPsec.Driver != ipsecDriverDryRun {
		platformRuntime, err := newLinuxRuntimeForIPsecCleanup(rt.Config)
		if err != nil {
			liveErr = err
		} else {
			defer platformRuntime.Close()
			sas, err := platformRuntime.ListIPsecSAs(ctx)
			if err != nil {
				liveErr = err
			} else {
				liveSAs = linkSAStatesFromIPsecSAs(sas)
			}
		}
	}
	build := buildLinkInspection(rt, common.State, common.Gossip, runtime, nil)
	storedSAs := []linkSAState(nil)
	if runtime != nil && runtime.IPsecReconcile != nil {
		storedSAs = runtime.IPsecReconcile.ActualSAs
	}
	return writeDebugRotateFromBuild(os.Stdout, build, filter, storedSAs, liveSAs, liveErr, "stored_sas", "live_sas")
}

func writeDebugRotateFromBuild(w io.Writer, build linkInspectionBuild, filter string, storedSAs, liveSAs []linkSAState, liveErr error, storedLabel, liveLabel string) error {
	liveErrText := ""
	if liveErr != nil {
		liveErrText = liveErr.Error()
	}
	view := inspect.BuildRotateDebug(inspect.RotateDebugInput{
		Inspection:        build.Inspection,
		PlannedSpecs:      build.PlannedSpecs,
		ReplannedDesired:  build.ReplannedDesired,
		ReplanIgnored:     build.ReplanIgnored,
		LastDesiredLinks:  build.LastDesiredLinks,
		DesiredPlanSource: build.DesiredPlanSource,
		Filter:            filter,
		StoredLabel:       storedLabel,
		LiveLabel:         liveLabel,
		StoredSAs:         inspectLinkSAs(storedSAs),
		LiveSAs:           inspectLinkSAs(liveSAs),
		LiveSAError:       liveErrText,
	})
	return inspecttext.WriteRotateDebug(w, view)
}

func linkSAStatesFromIPsecSAs(sas []ipsec.SAState) []linkSAState {
	out := make([]linkSAState, 0, len(sas))
	for _, sa := range sas {
		out = append(out, linkSAState{
			Name:            sa.Name,
			IKEAgeSeconds:   sa.IKEAgeSeconds,
			ChildAgeSeconds: sa.ChildAgeSeconds,
			InboundBytes:    sa.InboundBytes,
			InboundPackets:  sa.InboundPackets,
			InboundIdleSecs: sa.InboundIdleSecs,
			InboundKnown:    sa.InboundKnown,
			Peer:            sa.Peer,
			ChildSA:         sa.ChildSA,
			IKEState:        sa.IKEState,
			ChildState:      sa.ChildState,
			XFRMIfID:        sa.XFRMIfID,
			ReqID:           sa.ReqID,
			LocalIdentity:   sa.LocalIdentity,
			RemoteIdentity:  sa.RemoteIdentity,
			LocalEndpoint:   sa.LocalEndpoint,
			RemoteEndpoint:  sa.RemoteEndpoint,
			Endpoint:        sa.Endpoint,
			Established:     sa.Established,
		})
	}
	return out
}

func printManualPortRotateResult(mode string, result *manualPortRotateResult) {
	if result == nil {
		return
	}
	_ = inspecttext.WriteManualPortRotateResult(os.Stdout, mode, inspect.ManualPortRotateView{
		Zone:               result.Zone,
		PreviousGeneration: result.PreviousGeneration,
		CurrentGeneration:  result.CurrentGeneration,
		PreviousIKE:        result.PreviousIKE,
		PreviousNATT:       result.PreviousNATT,
		CurrentIKE:         result.CurrentIKE,
		CurrentNATT:        result.CurrentNATT,
		PreviousValidUntil: result.PreviousValidUntil,
	})
}

func rotateIPsecPortDirect(rt *Runtime) (*manualPortRotateResult, error) {
	boltStore, startup, err := openLinuxDaemonState(rt)
	if err != nil {
		return nil, err
	}
	defer boltStore.Close()
	defer startup.Common.Close()
	store, err := newPersistedDaemonStateStore(startup.Common, startup.Runtime, boltStore)
	if err != nil {
		return nil, err
	}
	common, runtime := store.readCommonAndRuntime()
	if common.State == nil || runtime == nil {
		return nil, fmt.Errorf("state owners are not initialized")
	}
	record, portRuntime, result, err := planLocalIPsecPortRotation(rt.Config, common.State, runtime, rt.Now())
	if err != nil {
		return nil, err
	}
	value, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	runtime.IPsecPortRecord = portRuntime
	committed, err := store.publishLocalProtocols(context.Background(), uint64(common.Revision), []corestate.LocalIntent{
		corestate.PutProtocolRecordIntent{Kind: corestate.ProtocolRecordIPsec, Zone: common.State.ManagedZone, Key: ipsec.RecordKeyPorts, Type: ipsec.RecordTypePorts, Value: value},
	}, runtime, rt.Now())
	if err != nil {
		return nil, err
	}
	if !committed.RuntimeCommitted && !committed.Common.Committed {
		return nil, fmt.Errorf("manual port rotate produced unchanged state")
	}
	return result, nil
}

func planLocalIPsecPortRotation(config *appConfig, verified *corestate.VerifiedState, ownersRuntime *linuxRuntimeState, now time.Time) (*ipsec.PortRecord, *ipsecPortRecordState, *manualPortRotateResult, error) {
	if config == nil {
		config = defaultAppConfig()
	}
	if verified == nil || verified.Network == nil {
		return nil, nil, nil, fmt.Errorf("verified state is nil")
	}
	if verified.ManagedZone == zone.RootZone || !verified.ManagedZone.Valid() {
		return nil, nil, nil, fmt.Errorf("managed zone is required")
	}
	if len(verified.IdentityPrivateKey) == 0 {
		return nil, nil, nil, fmt.Errorf("managed zone private key is required")
	}
	mode := config.IPsec.PortMode
	if mode == "" {
		mode = ipsec.PortModeFixed
	}
	if mode != ipsec.PortModeRange {
		return nil, nil, nil, fmt.Errorf("manual port rotate requires ipsec.port_mode=range, got %q", mode)
	}
	if now.IsZero() {
		now = time.Now()
	}
	existing := existingIPsecPortRecord(verified)
	previous := existing
	if previous == nil {
		previous = previousIPsecPortRecord(ownersRuntime)
	}
	prevState := ipsecPortRecordStateFromRuntime(ownersRuntime)
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
		return nil, nil, nil, err
	}
	runtime := &ipsecPortRecordState{
		Mode:       record.Mode,
		Range:      record.Range,
		Generation: record.Current.Generation,
		UpdatedAt:  record.UpdatedAt,
	}
	result := &manualPortRotateResult{
		Zone:              verified.ManagedZone,
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
	return record, runtime, result, nil
}
