package gossip

import (
	"sort"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func ZoneDigests(ns *zone.NetworkState) []ZoneDigest {
	if ns == nil {
		return nil
	}
	out := make([]ZoneDigest, 0, len(ns.Zones))
	for path, zs := range ns.Zones {
		if zs == nil {
			continue
		}
		out = append(out, ZoneDigest{
			Zone:     path,
			RootHash: ZoneRoot(zs),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Zone < out[j].Zone
	})
	return out
}

func ZoneRoot(zs *zone.ZoneState) []byte {
	if zs == nil {
		return nil
	}
	parts := make([][]byte, 0, 1+len(zs.Delegations)+len(zs.Records))
	parts = append(parts, higgscrypto.AuthorityHash(zs.Authority))

	delegationZones := make([]string, 0, len(zs.Delegations))
	for path := range zs.Delegations {
		delegationZones = append(delegationZones, path.String())
	}
	sort.Strings(delegationZones)
	for _, path := range delegationZones {
		delegation := zs.Delegations[zone.ZonePath(path)]
		if delegation == nil {
			continue
		}
		parts = append(parts, higgscrypto.Hash(
			[]byte("delegation"),
			[]byte(path),
			delegation.AuthorityHash,
			delegation.Signature,
		))
	}

	recordKeys := make([]string, 0, len(zs.Records))
	for key := range zs.Records {
		recordKeys = append(recordKeys, key)
	}
	sort.Strings(recordKeys)
	for _, key := range recordKeys {
		record := zs.Records[key]
		if record == nil {
			continue
		}
		parts = append(parts, higgscrypto.Hash(
			[]byte("record"),
			[]byte(key),
			higgscrypto.RecordHash(record),
		))
	}
	return higgscrypto.Hash(parts...)
}
