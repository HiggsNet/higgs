package inspect

import (
	"testing"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestDebugIPsecPortsPreferContactAndRuntimeEndpoints(t *testing.T) {
	spec := &ipsec.TransportLinkSpec{
		Generation: 3,
		ContactPoints: []ipsec.ContactPoint{
			{Generation: 3, IKEPort: 30004, NATTPort: 33403},
			{Generation: 2, IKEPort: 30002, NATTPort: 33401},
		},
	}

	if got := DebugPortGenerationSummary(spec, LinkRotation{RemoteGeneration: 1, StagedGeneration: 2}); got != "3/1/2" {
		t.Fatalf("port generation summary = %q", got)
	}
	if got := DebugPortGenerationSummary(nil, LinkRotation{RemoteGeneration: 3}); got != "-/3/0" {
		t.Fatalf("missing spec port generation summary = %q", got)
	}
	if got := DebugPortSummary(spec, "198.51.100.20:4500", "198.51.100.20:33403", 2); got != "4500/33403/33403/33401" {
		t.Fatalf("port summary = %q", got)
	}
	if got := DebugRemotePort(spec, "198.51.100.20:4500"); got != "33403" {
		t.Fatalf("remote port = %q", got)
	}
	if got := DebugStagedPort(spec, 2); got != "33401" {
		t.Fatalf("staged port = %q", got)
	}
	if got := DebugEndpointPort("[2001:db8::1]:4500"); got != "4500" {
		t.Fatalf("endpoint port = %q", got)
	}
}
