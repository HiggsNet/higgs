package text

import (
	"io"
	"time"

	"github.com/Catofes/higgs/internal/inspect"
)

func WriteEndpointsDebug(w io.Writer, view inspect.EndpointDebugView) error {
	out := newLineWriter(w)
	out.LineIf(view.ReflectorError != "", "reflector_error: %s", view.ReflectorError)
	out.Linef("local_candidates: %d", len(view.LocalCandidates))
	for _, ep := range view.LocalCandidates {
		out.Linef("candidate addr=%s port=%d scope=%s priority=%d source=%s",
			ep.Address,
			ep.Port,
			ep.Scope,
			ep.Priority,
			ep.Source,
		)
	}
	out.Linef("discovered_peers: %d", len(view.DiscoveredPeers))
	for _, peer := range view.DiscoveredPeers {
		out.Linef("peer %s endpoints=%d", peer.PeerID, len(peer.Endpoints))
		for _, ep := range peer.Endpoints {
			out.Linef("  endpoint addr=%s port=%d scope=%s priority=%d protocol=%s source=%s last_observed=%s",
				ep.Address,
				ep.Port,
				ep.Scope,
				ep.Priority,
				ep.Protocol,
				dash(ep.Source),
				formatEndpointUnixTime(ep.LastObserved),
			)
		}
	}
	return out.Err()
}

func formatEndpointUnixTime(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}
