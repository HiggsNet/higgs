package zone

// CloneNetworkState returns a complete detached copy of ns. Validation
// functions are immutable configuration and are intentionally retained.
func CloneNetworkState(ns *NetworkState) *NetworkState {
	if ns == nil {
		return nil
	}
	out := &NetworkState{
		GlobalRoot:     cloneBytes(ns.GlobalRoot),
		RecordVerifier: ns.RecordVerifier,
		RecordHasher:   ns.RecordHasher,
	}
	if ns.Zones != nil {
		out.Zones = make(map[ZonePath]*ZoneState, len(ns.Zones))
		for path, state := range ns.Zones {
			out.Zones[path] = cloneZoneState(state)
		}
	}
	return out
}

// CloneNetworkStateForZone returns a copy-on-write NetworkState candidate for
// mutations confined to path. The NetworkState root and Zones map are
// detached, path is cloned completely, and every other zone remains shared
// and must be treated as immutable.
//
// MerkleRoot and GlobalRoot are copied as ordinary data. They are not used as
// mutable digest caches, so target-zone COW does not introduce a cache
// invalidation protocol.
func CloneNetworkStateForZone(ns *NetworkState, path ZonePath) *NetworkState {
	if ns == nil {
		return nil
	}
	out := *ns
	out.GlobalRoot = cloneBytes(ns.GlobalRoot)
	if ns.Zones == nil {
		out.Zones = make(map[ZonePath]*ZoneState)
		return &out
	}
	out.Zones = make(map[ZonePath]*ZoneState, len(ns.Zones)+1)
	for zonePath, state := range ns.Zones {
		out.Zones[zonePath] = state
	}
	if state, ok := ns.Zones[path]; ok {
		out.Zones[path] = cloneZoneState(state)
	}
	return &out
}

func cloneZoneState(state *ZoneState) *ZoneState {
	if state == nil {
		return nil
	}
	out := &ZoneState{
		Path:        state.Path,
		Authority:   cloneZoneAuthority(state.Authority),
		ParentProof: cloneDelegationSlice(state.ParentProof),
		MerkleRoot:  cloneBytes(state.MerkleRoot),
	}
	if state.Delegations != nil {
		out.Delegations = make(map[ZonePath]*Delegation, len(state.Delegations))
		for path, delegation := range state.Delegations {
			out.Delegations[path] = cloneDelegation(delegation)
		}
	}
	if state.Revocations != nil {
		out.Revocations = make(map[ZonePath]*DelegationRevocation, len(state.Revocations))
		for path, revocation := range state.Revocations {
			out.Revocations[path] = cloneDelegationRevocation(revocation)
		}
	}
	if state.Records != nil {
		out.Records = make(map[string]*Record, len(state.Records))
		for key, record := range state.Records {
			out.Records[key] = cloneRecord(record)
		}
	}
	if state.RecordHistory != nil {
		out.RecordHistory = make(map[string][]*Record, len(state.RecordHistory))
		for key, history := range state.RecordHistory {
			if history == nil {
				out.RecordHistory[key] = nil
				continue
			}
			cloned := make([]*Record, len(history))
			for i, record := range history {
				cloned[i] = cloneRecord(record)
			}
			out.RecordHistory[key] = cloned
		}
	}
	return out
}

func cloneZoneAuthority(authority *ZoneAuthority) *ZoneAuthority {
	if authority == nil {
		return nil
	}
	out := &ZoneAuthority{
		Zone:      authority.Zone,
		Epoch:     authority.Epoch,
		Threshold: authority.Threshold,
	}
	if authority.Keys != nil {
		out.Keys = make([]AuthorizedKey, len(authority.Keys))
		for i, key := range authority.Keys {
			out.Keys[i] = AuthorizedKey{
				Key:          cloneBytes(key.Key),
				NotBefore:    key.NotBefore,
				NotAfter:     key.NotAfter,
				Capabilities: cloneCapabilities(key.Capabilities),
			}
		}
	}
	return out
}

func cloneCapabilities(capabilities []Capability) []Capability {
	if capabilities == nil {
		return nil
	}
	out := make([]Capability, len(capabilities))
	for i, capability := range capabilities {
		out[i] = Capability{
			Permissions: cloneSlice(capability.Permissions),
			KeyPrefix:   capability.KeyPrefix,
		}
	}
	return out
}

func cloneDelegationSlice(delegations []*Delegation) []*Delegation {
	if delegations == nil {
		return nil
	}
	out := make([]*Delegation, len(delegations))
	for i, delegation := range delegations {
		out[i] = cloneDelegation(delegation)
	}
	return out
}

func cloneDelegation(delegation *Delegation) *Delegation {
	if delegation == nil {
		return nil
	}
	out := &Delegation{
		ZoneName:       delegation.ZoneName,
		Scope:          delegation.Scope,
		AuthorityEpoch: delegation.AuthorityEpoch,
		AuthorityHash:  cloneBytes(delegation.AuthorityHash),
		Authority:      *cloneZoneAuthority(&delegation.Authority),
		SignedBy:       cloneBytes(delegation.SignedBy),
		Signature:      cloneBytes(delegation.Signature),
	}
	if delegation.ExpiresAt != nil {
		expiresAt := *delegation.ExpiresAt
		out.ExpiresAt = &expiresAt
	}
	return out
}

func cloneDelegationRevocation(revocation *DelegationRevocation) *DelegationRevocation {
	if revocation == nil {
		return nil
	}
	out := *revocation
	out.RevokedAuthorityHash = cloneBytes(revocation.RevokedAuthorityHash)
	out.SignedBy = cloneBytes(revocation.SignedBy)
	out.Signature = cloneBytes(revocation.Signature)
	return &out
}

func cloneRecord(record *Record) *Record {
	if record == nil {
		return nil
	}
	out := *record
	out.Value = cloneBytes(record.Value)
	out.ValueHash = cloneBytes(record.ValueHash)
	out.PrevHash = cloneBytes(record.PrevHash)
	out.SignedBy = cloneBytes(record.SignedBy)
	out.Signature = cloneBytes(record.Signature)
	return &out
}

func cloneBytes(in []byte) []byte {
	return cloneSlice(in)
}

func cloneSlice[T any](in []T) []T {
	if in == nil {
		return nil
	}
	out := make([]T, len(in))
	copy(out, in)
	return out
}
