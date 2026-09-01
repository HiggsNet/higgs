package main

import corestate "github.com/HiggsNet/photon/pkg/core/state"

func (sr *SyncRuntime) publishIPsecRecords(state *stateFile) error {
	plan, err := sr.ipsecProtocolPlan(verifiedStateForTest(state), linuxRuntimeStateFromLegacy(state))
	if err != nil {
		return err
	}
	changed := false
	for _, raw := range plan.Intents {
		intent := raw.(corestate.PutProtocolRecordIntent)
		record, err := buildSignedRecordAt(state, intent.Zone, intent.Key, intent.Value, intent.Type, sr.now())
		if err != nil {
			return err
		}
		if err := state.Network.PutAt(record, sr.now()); err != nil {
			return err
		}
		changed = true
	}
	if !ipsecTransportKeyStateEqual(state.IPsecTransportKey, plan.TransportKey) {
		state.IPsecTransportKey = cloneIPsecTransportKeyState(plan.TransportKey)
		changed = true
	}
	if !ipsecPortRecordStateEqual(state.IPsecPortRecord, plan.PortRecord) {
		state.IPsecPortRecord = cloneIPsecPortRecordState(plan.PortRecord)
		changed = true
	}
	if !changed {
		return nil
	}
	if err := sr.App.SaveState(state); err != nil {
		return err
	}
	if sr != nil && state != nil {
		sr.logger().Debug("ipsec", "publish_saved", map[string]any{"managed_zone": state.ManagedZone})
	}
	return nil
}
