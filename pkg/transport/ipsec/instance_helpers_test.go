package ipsec

func stagedRuntimeID(inst LinkInstance, generation uint64) string {
	return RuntimeConnectionID(firstNonEmptyString(inst.LinkID, inst.ID), generation, inst.TransportKind)
}

func runtimeSpecForPortGeneration(spec TransportLinkSpec, generation uint64) TransportLinkSpec {
	spec.Generation = generation
	runtimeGeneration := runtimeGenerationForPortGeneration(generation)
	spec.AddressEpoch = runtimeGeneration
	if spec.LinkID != "" {
		spec.TransportID = RuntimeConnectionID(spec.LinkID, runtimeGeneration, spec.Provider)
		spec.XFRMIfID = RuntimeXFRMIfID(spec.LinkID, runtimeGeneration, spec.Provider)
	} else {
		spec.XFRMIfID = StableXFRMIfID(spec.LocalZone, spec.PeerZone, spec.TransportID)
	}
	spec.InterfaceName = StableInterfaceName(spec.XFRMIfID)
	return spec
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
