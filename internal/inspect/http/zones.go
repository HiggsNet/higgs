package http

import (
	"encoding/hex"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

type ZonesResponse struct {
	Zones      []ZoneSummaryJSON `json:"zones"`
	GlobalRoot string            `json:"global_root"`
}

type ZoneSummaryJSON struct {
	Path        string `json:"path"`
	Records     int    `json:"records"`
	Delegations int    `json:"delegations"`
	Revocations int    `json:"revocations"`
	Revoked     bool   `json:"revoked"`
	RootHashHex string `json:"root_hash"`
}

func ZonesFromNetwork(ns *zone.NetworkState, nowUnix int64) ZonesResponse {
	if ns == nil {
		return ZonesResponse{Zones: []ZoneSummaryJSON{}}
	}
	paths := make([]zone.ZonePath, 0, len(ns.Zones))
	for path := range ns.Zones {
		paths = append(paths, path)
	}
	sortZonePaths(paths)
	zones := make([]ZoneSummaryJSON, 0, len(paths))
	now := time.Unix(nowUnix, 0)
	for _, path := range paths {
		zs := ns.Zones[path]
		if zs == nil {
			continue
		}
		rootHash := ""
		if zs.Authority != nil {
			rootHash = hex.EncodeToString(photoncrypto.AuthorityHash(zs.Authority))
		}
		zones = append(zones, ZoneSummaryJSON{
			Path:        string(path),
			Records:     len(zs.Records),
			Delegations: len(zs.Delegations),
			Revocations: len(zs.Revocations),
			Revoked:     ns.IsZoneRevoked(path, now),
			RootHashHex: rootHash,
		})
	}
	globalRoot := ""
	if root := globalRootHash(gossip.ZoneDigests(ns)); root != nil {
		globalRoot = hex.EncodeToString(root)
	}
	return ZonesResponse{
		Zones:      zones,
		GlobalRoot: globalRoot,
	}
}

func sortZonePaths(paths []zone.ZonePath) {
	inspect.SortZonePaths(paths)
}

func globalRootHash(digests []gossip.ZoneDigest) []byte {
	parts := make([][]byte, 0, len(digests)*2)
	for _, digest := range digests {
		parts = append(parts, []byte(digest.Zone), digest.RootHash)
	}
	return photoncrypto.Hash(parts...)
}
