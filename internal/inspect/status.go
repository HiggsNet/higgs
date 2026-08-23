package inspect

import (
	"sort"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	StatusModeRunning  = "running"
	StatusModeAutoJoin = "auto-join"
	StatusModeNoState  = "no-state"
)

type StatusInput struct {
	DaemonOnline bool
	ManagedZone  zone.ZonePath
	Admission    AdmissionDiagnosis
	Peers        []PeerStatusInfo
	Links        LinkInspection
}

type StatusCount struct {
	State string
	Count int
}

type StatusPeerSummary struct {
	Total    int
	LastSync int64
	States   []StatusCount
}

type StatusLinkSummary struct {
	Desired   int
	Total     int
	Up        int
	States    []StatusCount
	Health    []StatusCount
	LastError string
}

type StatusView struct {
	DaemonOnline  bool
	ManagedZone   zone.ZonePath
	Mode          string
	AutoJoinStage string
	Admission     AdmissionDiagnosis
	Peers         StatusPeerSummary
	Links         StatusLinkSummary
}

func BuildStatus(input StatusInput) StatusView {
	view := StatusView{
		DaemonOnline: input.DaemonOnline,
		ManagedZone:  input.ManagedZone,
		Mode:         StatusModeRunning,
		Admission:    input.Admission,
	}
	if view.ManagedZone == "" {
		view.ManagedZone = input.Admission.ManagedZone
	}
	if view.ManagedZone == "" {
		view.Mode = StatusModeNoState
	}
	if input.Admission.Pending {
		view.Mode = StatusModeAutoJoin
		view.AutoJoinStage = AutoJoinStage(input.Admission.Reason)
	}

	peerStates := make(map[string]int)
	for _, peer := range input.Peers {
		peerStates[statusName(peer.State)]++
		if peer.LastSyncUnix > view.Peers.LastSync {
			view.Peers.LastSync = peer.LastSyncUnix
		}
	}
	view.Peers.Total = len(input.Peers)
	view.Peers.States = sortedStatusCounts(peerStates)

	linkStates := make(map[string]int)
	healthStates := make(map[string]int)
	view.Links.Desired = input.Links.Summary.DesiredLinks
	view.Links.Total = input.Links.Summary.LinkInstances
	view.Links.LastError = input.Links.Summary.LastError
	for _, link := range input.Links.Links {
		state := statusName(link.State)
		linkStates[state]++
		if state == "up" {
			view.Links.Up++
		}
		if link.Health != nil {
			healthStates[statusName(link.Health.State)]++
		}
	}
	view.Links.States = sortedStatusCounts(linkStates)
	view.Links.Health = sortedStatusCounts(healthStates)
	return view
}

func AutoJoinStage(reason string) string {
	switch reason {
	case AdmissionReasonMissingZoneKey:
		return "preparing_identity"
	case AdmissionReasonNoBootstrapSync, AdmissionReasonMissingParentZone:
		return "syncing_parent"
	case AdmissionReasonMissingDelegation:
		return "awaiting_delegation"
	case AdmissionReasonDelegationKeyMismatch, AdmissionReasonVerifyDelegationFailed, AdmissionReasonVerifyChainFailed:
		return "delegation_invalid"
	case AdmissionReasonWaitingForAdoption:
		return "adopting"
	default:
		return "pending"
	}
}

func sortedStatusCounts(counts map[string]int) []StatusCount {
	states := make([]string, 0, len(counts))
	for state := range counts {
		states = append(states, state)
	}
	sort.Strings(states)
	out := make([]StatusCount, 0, len(states))
	for _, state := range states {
		out = append(out, StatusCount{State: state, Count: counts[state]})
	}
	return out
}

func statusName(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
