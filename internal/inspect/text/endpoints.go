package text

import (
	"io"

	"github.com/HiggsNet/photon/internal/inspect"
)

func WriteEndpointsDebug(w io.Writer, view inspect.EndpointDebugView) error {
	out := newLineWriter(w)
	out.Linef("published_peers: %d", len(view.Peers))
	for _, peer := range view.Peers {
		out.Linef("peer %s endpoints=%d local=%t", peer.PeerID, len(peer.Endpoints), peer.PeerID == view.ManagedPeerID)
		for _, ep := range peer.Endpoints {
			out.Linef("  endpoint addr=%s port=%d scope=%s priority=%d protocol=%s source=%s last_observed=%s",
				ep.Address,
				ep.Port,
				ep.Scope,
				ep.Priority,
				ep.Protocol,
				dash(ep.Source),
				formatUnixTime(ep.LastObserved),
			)
		}
	}
	return out.Err()
}
