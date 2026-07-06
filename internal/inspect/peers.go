package inspect

import (
	"fmt"
	"sort"
)

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
