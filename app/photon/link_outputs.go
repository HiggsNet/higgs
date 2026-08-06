package main

import (
	"net/netip"
	"sort"
	"strconv"

	photonstate "github.com/Catofes/photon/internal/state"
	"github.com/Catofes/photon/pkg/core/zone"
	"github.com/Catofes/photon/pkg/transport/ipsec"
)

// linkOutputsFromState projects provider-owned runtime state into the common
// Babel-facing consumer contract. It deliberately carries no owner, SA name,
// action, rotate phase, or other lifecycle input.
func linkOutputsFromState(state *stateFile) []photonstate.LinkOutput {
	if state == nil {
		return nil
	}
	desired := make(map[string][]desiredLinkState)
	if state.IPsecReconcile != nil {
		for _, item := range state.IPsecReconcile.Desired {
			desired[item.InstanceID] = append(desired[item.InstanceID], item)
		}
	}
	ids := sortedLinkInstanceIDs(state.LinkInstances)
	out := make([]photonstate.LinkOutput, 0, len(ids)*2)
	for _, id := range ids {
		inst := state.LinkInstances[id]
		wants := desired[id]
		if len(wants) == 0 {
			wants = []desiredLinkState{{}}
		}
		for i, want := range wants {
			base := newIPsecLinkOutput(inst, want)
			if len(wants) > 1 && base.PathKey == "" {
				base.ID += "#path-" + strconv.Itoa(i)
			}
			if inst.StagedInterfaceName != "" {
				// During rotate the current runtime must be projected only from its
				// persisted observation. The desired addresses may already describe
				// the staged generation and must not be guessed onto the old link.
				base.InterfaceName = inst.InterfaceName
				base.LocalAddr = parseScopedAddr(inst.LocalTunnelAddr)
				base.PeerAddr = parseScopedAddr(inst.PeerTunnelAddr)
				base.Readiness.Interface = interfaceReadiness(base.InterfaceName, base.State)
			}
			out = append(out, base)
			if i != 0 || inst.StagedInterfaceName == "" {
				continue
			}
			staged := base
			staged.ID = runtimeLinkOutputID(firstNonEmpty(inst.LinkID, inst.ID, want.LinkID, want.InstanceID), photonstate.LinkRuntimeStaged)
			staged.InterfaceName = inst.StagedInterfaceName
			staged.LocalAddr = parseScopedAddr(inst.StagedLocalTunnelAddr)
			staged.PeerAddr = parseScopedAddr(inst.StagedPeerTunnelAddr)
			staged.Generation = inst.StagedGeneration
			staged.RuntimeRole = photonstate.LinkRuntimeStaged
			staged.Endpoint = ""
			staged.Readiness.Interface = interfaceReadiness(staged.InterfaceName, staged.State)
			out = append(out, staged)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func firstNonEmptyZone(values ...zone.ZonePath) zone.ZonePath {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func newIPsecLinkOutput(inst linkInstanceState, desired desiredLinkState) photonstate.LinkOutput {
	id := firstNonEmpty(inst.LinkID, desired.LinkID, inst.ID, desired.InstanceID)
	provider := inst.TransportKind
	if provider == "" {
		provider = ipsec.ProviderStrongSwan
	}
	iface := firstNonEmpty(inst.InterfaceName, desired.InterfaceName)
	local := parseScopedAddr(firstNonEmpty(inst.LocalTunnelAddr, desired.LocalTunnelAddr))
	peer := parseScopedAddr(firstNonEmpty(inst.PeerTunnelAddr, desired.PeerTunnelAddr))
	netns := firstNonEmpty(scopedNetNS(inst.LocalTunnelAddr), scopedNetNS(inst.PeerTunnelAddr), scopedNetNS(desired.LocalTunnelAddr), scopedNetNS(desired.PeerTunnelAddr))
	return photonstate.LinkOutput{
		ID:             id,
		GroupID:        firstNonEmpty(inst.GroupID, desired.GroupID),
		PeerZone:       firstNonEmptyZone(inst.PeerZone, desired.PeerZone),
		Provider:       provider,
		PathKey:        firstNonEmpty(inst.PathKey, desired.PathKey),
		NetNS:          netns,
		InterfaceName:  iface,
		LocalAddr:      local,
		PeerAddr:       peer,
		Generation:     inst.RemoteGeneration,
		RuntimeRole:    photonstate.LinkRuntimeActive,
		State:          inst.ActualState,
		Readiness:      baseLinkReadiness(inst.ActualState, iface),
		Endpoint:       firstNonEmpty(inst.Endpoint, desired.Endpoint),
		LastError:      inst.LastError,
		LastTransition: inst.LastTransition,
	}
}

func parseScopedAddr(value string) netip.Addr {
	addr, _ := netip.ParseAddr(stripScope(value))
	return addr
}

func runtimeLinkOutputID(linkID, role string) string {
	if role == "" || role == photonstate.LinkRuntimeActive {
		return linkID
	}
	return linkID + "#" + role
}

func baseLinkReadiness(state, iface string) photonstate.LinkReadiness {
	ready := photonstate.LinkReadiness{Session: photonstate.LinkReadyNotReady, Interface: interfaceReadiness(iface, state), Routing: photonstate.LinkReadyUnknown, Health: photonstate.LinkReadyUnknown}
	if state == "up" {
		ready.Session = photonstate.LinkReadyReady
	}
	return ready
}

func interfaceReadiness(iface, state string) string {
	if iface != "" && state != "" && state != "removing" && state != "failed" {
		return photonstate.LinkReadyReady
	}
	return photonstate.LinkReadyNotReady
}
