package inspect

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Catofes/higgs/pkg/core/zone"
)

type PeerSetInput struct {
	RuntimeIDs   []string
	BootstrapIDs []string
	SignedIDs    []string
	LocalIDs     []string
}

type PeerEndpointInput struct {
	BootstrapAddr  string
	Signed         []PeerSignedEndpoint
	SelectedAddr   string
	ObservedAddr   string
	ObservedSource string
	Grace          []PeerGraceEndpoint
}

type PeerSignedEndpoint struct {
	Address      string
	Port         uint16
	Protocol     string
	Scope        string
	Source       string
	Priority     int
	LastObserved int64
}

type PeerGraceEndpoint struct {
	Addr string
}

type PeerEndpointView struct {
	Addr         string `json:"addr"`
	Address      string `json:"address,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Source       string `json:"source,omitempty"`
	Priority     int    `json:"priority,omitempty"`
	LastObserved int64  `json:"last_observed,omitempty"`
	Selected     bool   `json:"selected,omitempty"`
}

// PeerStatusInfo is the derived runtime status view for a peer. Producers
// compute it from committed state and runtime observations; presenters render
// it without depending on app-private stateFile internals.
type PeerStatusInfo struct {
	PeerID            string        `json:"peer_id"`
	Zone              zone.ZonePath `json:"zone"`
	State             string        `json:"state"`
	Reason            string        `json:"reason,omitempty"`
	Detail            string        `json:"detail,omitempty"`
	LastSeenUnix      int64         `json:"last_seen_unix,omitempty"`
	LastSyncUnix      int64         `json:"last_sync_unix,omitempty"`
	LastEndpointUnix  int64         `json:"last_endpoint_change_unix,omitempty"`
	LastReconcileUnix int64         `json:"last_reconcile_unix,omitempty"`
	DesiredLinks      int           `json:"desired_links,omitempty"`
	ActualLinks       int           `json:"actual_links,omitempty"`
	UpLinks           int           `json:"up_links,omitempty"`
	OfflineSinceUnix  int64         `json:"offline_since_unix,omitempty"`
	NextCleanupUnix   int64         `json:"next_cleanup_unix,omitempty"`
}

func BuildPeerIDs(input PeerSetInput) []string {
	local := make(map[string]bool, len(input.LocalIDs))
	for _, id := range input.LocalIDs {
		if id != "" {
			local[id] = true
		}
	}
	seen := map[string]bool{}
	add := func(ids []string) {
		for _, id := range ids {
			if id == "" || local[id] || seen[id] {
				continue
			}
			seen[id] = true
		}
	}
	add(input.RuntimeIDs)
	add(input.BootstrapIDs)
	add(input.SignedIDs)
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return ZonePathLess(out[i], out[j]) })
	return out
}

func PeerKnown(input PeerSetInput, peerID string) bool {
	if peerID == "" {
		return false
	}
	for _, local := range input.LocalIDs {
		if peerID == local {
			return false
		}
	}
	for _, ids := range [][]string{input.RuntimeIDs, input.BootstrapIDs, input.SignedIDs} {
		for _, id := range ids {
			if peerID == id {
				return true
			}
		}
	}
	return false
}

func ZonePathLess(a, b string) bool {
	aLabels, aOK := zonePathLabels(a)
	bLabels, bOK := zonePathLabels(b)
	if !aOK || !bOK {
		return a < b
	}
	for i := 0; i < len(aLabels) && i < len(bLabels); i++ {
		if aLabels[i] != bLabels[i] {
			return aLabels[i] < bLabels[i]
		}
	}
	if len(aLabels) != len(bLabels) {
		return len(aLabels) < len(bLabels)
	}
	return a < b
}

func zonePathLabels(path string) ([]string, bool) {
	zp := zone.ZonePath(path)
	if !zp.Valid() {
		return nil, false
	}
	if zp.IsRoot() {
		return nil, true
	}
	labels := strings.Split(strings.TrimSuffix(path, "."), ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return labels, true
}

func BuildPeerEndpoints(input PeerEndpointInput) []PeerEndpointView {
	var out []PeerEndpointView
	appendEndpoint := func(ep PeerEndpointView) {
		if ep.Addr == "" && ep.Address != "" && ep.Port != 0 {
			ep.Addr = fmt.Sprintf("%s:%d", ep.Address, ep.Port)
		}
		if ep.Protocol == "" {
			ep.Protocol = "udp"
		}
		for i := range out {
			if out[i].Addr == ep.Addr && out[i].Source == ep.Source {
				if ep.Selected {
					out[i].Selected = true
				}
				return
			}
		}
		out = append(out, ep)
	}
	if input.BootstrapAddr != "" {
		appendEndpoint(PeerEndpointView{
			Addr:     input.BootstrapAddr,
			Source:   "bootstrap",
			Selected: input.SelectedAddr == input.BootstrapAddr,
		})
	}
	for _, ep := range input.Signed {
		addr := ""
		if ep.Address != "" && ep.Port != 0 {
			addr = fmt.Sprintf("%s:%d", ep.Address, ep.Port)
		}
		appendEndpoint(PeerEndpointView{
			Addr:         addr,
			Address:      ep.Address,
			Port:         ep.Port,
			Protocol:     ep.Protocol,
			Scope:        ep.Scope,
			Source:       firstNonEmpty(ep.Source, "signed"),
			Priority:     ep.Priority,
			LastObserved: ep.LastObserved,
			Selected:     input.SelectedAddr == addr,
		})
	}
	if input.SelectedAddr != "" {
		appendEndpoint(PeerEndpointView{Addr: input.SelectedAddr, Source: "selected", Selected: true})
	}
	if input.ObservedAddr != "" {
		appendEndpoint(PeerEndpointView{
			Addr:     input.ObservedAddr,
			Source:   firstNonEmpty(input.ObservedSource, "observed"),
			Selected: input.SelectedAddr == "",
		})
	}
	for _, grace := range input.Grace {
		appendEndpoint(PeerEndpointView{Addr: grace.Addr, Source: "observed_grace"})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Selected != out[j].Selected {
			return out[i].Selected
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}
