package inspect

import (
	"fmt"
	"net"

	"github.com/Catofes/higgs/pkg/transport/ipsec"
)

func DebugPortGenerationSummary(spec *ipsec.TransportLinkSpec, rotation LinkRotation) string {
	return fmt.Sprintf("%s/%d/%d", debugSelectedGeneration(spec), rotation.RemoteGeneration, rotation.StagedGeneration)
}

func DebugPortSummary(spec *ipsec.TransportLinkSpec, selectedEndpoint, runtimeEndpoint string, stagedGeneration uint64) string {
	return fmt.Sprintf("%s/%s/%s/%s",
		debugDash(debugLocalPort(spec)),
		debugDash(DebugRemotePort(spec, selectedEndpoint)),
		debugDash(DebugEndpointPort(runtimeEndpoint)),
		debugDash(DebugStagedPort(spec, stagedGeneration)),
	)
}

func DebugRemotePort(spec *ipsec.TransportLinkSpec, endpoint string) string {
	if spec != nil {
		if point, ok := firstContactPointForDebug(spec.ContactPoints); ok {
			return debugContactPort(point)
		}
	}
	return DebugEndpointPort(endpoint)
}

func DebugStagedPort(spec *ipsec.TransportLinkSpec, stagedGeneration uint64) string {
	if spec == nil || stagedGeneration == 0 {
		return ""
	}
	for _, point := range spec.ContactPoints {
		if point.Generation == stagedGeneration {
			return debugContactPort(point)
		}
	}
	return ""
}

func DebugEndpointPort(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ""
	}
	return port
}

func debugSelectedGeneration(spec *ipsec.TransportLinkSpec) string {
	if spec == nil {
		return "-"
	}
	return fmt.Sprintf("%d", spec.Generation)
}

func debugLocalPort(spec *ipsec.TransportLinkSpec) string {
	if spec == nil {
		return ""
	}
	if spec.LocalIKEPort != 0 {
		return fmt.Sprintf("%d", spec.LocalIKEPort)
	}
	return fmt.Sprintf("%d", ipsec.DefaultNATTPort)
}

func debugContactPort(point ipsec.ContactPoint) string {
	if point.NATTPort != 0 {
		return fmt.Sprintf("%d", point.NATTPort)
	}
	if point.IKEPort != 0 {
		return fmt.Sprintf("%d", point.IKEPort)
	}
	return ""
}

func firstContactPointForDebug(points []ipsec.ContactPoint) (ipsec.ContactPoint, bool) {
	for _, point := range points {
		return point, true
	}
	return ipsec.ContactPoint{}, false
}

func debugDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
