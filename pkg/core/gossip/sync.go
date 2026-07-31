package gossip

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

var (
	ErrZoneSnapshotTooLarge = errors.New("zone snapshot exceeds quota")
	ErrUntrustedZone        = errors.New("zone is not under a trusted root")
)

type SyncLimits struct {
	MaxZones   int
	MaxRecords int
	MaxBytes   int
}

type ApplyResult struct {
	Zone       zone.ZonePath
	Records    int
	Delegation int
}

func DefaultSyncLimits() SyncLimits {
	return SyncLimits{
		MaxZones:   16,
		MaxRecords: 1024,
		MaxBytes:   DefaultMaxMessage,
	}
}

func Snapshot(ns *zone.NetworkState, path zone.ZonePath) (*ZoneSnapshot, error) {
	if ns == nil {
		return nil, errors.New("network state is nil")
	}
	zs := ns.Zones[path]
	if zs == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	return &ZoneSnapshot{
		Zone:        path,
		Authority:   cloneAuthority(zs.Authority),
		ParentProof: snapshotParentProof(ns, path, zs),
		Delegations: cloneDelegationMap(zs.Delegations),
		Revocations: cloneRevocationMap(zs.Revocations),
		Records:     cloneRecordMap(zs.Records),
	}, nil
}

func RecordSnapshotFor(ns *zone.NetworkState, fetch *FetchRecord) (*RecordSnapshot, error) {
	if ns == nil {
		return nil, errors.New("network state is nil")
	}
	if fetch == nil || !fetch.Zone.Valid() || fetch.Key == "" {
		return nil, zone.ErrInvalidFQKey
	}
	zs := ns.Zones[fetch.Zone]
	if zs == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, fetch.Zone)
	}
	for _, record := range append([]*zone.Record(nil), zs.RecordHistory[fetch.Key]...) {
		if record != nil && (fetch.Version == 0 || record.Version == fetch.Version) {
			return &RecordSnapshot{Zone: fetch.Zone, Record: cloneRecord(record)}, nil
		}
	}
	if record := zs.Records[fetch.Key]; record != nil && (fetch.Version == 0 || record.Version == fetch.Version) {
		return &RecordSnapshot{Zone: fetch.Zone, Record: cloneRecord(record)}, nil
	}
	return nil, fmt.Errorf("%w: %s/%s", zone.ErrRecordNotFound, fetch.Zone, fetch.Key)
}

func ApplySnapshot(ns *zone.NetworkState, snapshot *ZoneSnapshot, now time.Time, limits SyncLimits) (*ApplyResult, error) {
	if ns == nil {
		return nil, errors.New("network state is nil")
	}
	if snapshot == nil {
		return nil, errors.New("zone snapshot is nil")
	}
	if !snapshot.Zone.Valid() {
		return nil, zone.ErrInvalidZonePath
	}
	if ns.IsZoneRevoked(snapshot.Zone, now) {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneRevoked, snapshot.Zone)
	}
	if limits == (SyncLimits{}) {
		limits = DefaultSyncLimits()
	}
	if err := checkSnapshotLimits(snapshot, limits); err != nil {
		return nil, err
	}

	candidate := cloneNetworkState(ns)
	candidate.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
	active := candidate.Zones[snapshot.Zone]
	candidate.Zones[snapshot.Zone] = snapshotZoneState(snapshot)
	if err := higgscrypto.VerifyChain(candidate, snapshot.Zone, now); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUntrustedZone, err)
	}

	zs := candidate.Zones[snapshot.Zone]
	for child, delegation := range zs.Delegations {
		if err := higgscrypto.VerifyDelegation(delegation, zs.Authority, snapshot.Zone, now); err != nil {
			return nil, fmt.Errorf("verify delegation %s: %w", child, err)
		}
	}
	for child, revocation := range zs.Revocations {
		if err := higgscrypto.VerifyDelegationRevocation(revocation, zs.Authority, snapshot.Zone, now); err != nil {
			return nil, fmt.Errorf("verify revocation %s: %w", child, err)
		}
	}

	if active == nil {
		active = zone.NewZoneState(snapshot.Zone, cloneAuthority(snapshot.Authority))
	} else {
		active.Authority = cloneAuthority(snapshot.Authority)
	}
	candidate.Zones[snapshot.Zone] = active
	active.ParentProof = cloneDelegationSlice(snapshot.ParentProof)
	if active.Delegations == nil {
		active.Delegations = make(map[zone.ZonePath]*zone.Delegation)
	}
	if active.Revocations == nil {
		active.Revocations = make(map[zone.ZonePath]*zone.DelegationRevocation)
	}
	if active.Records == nil {
		active.Records = make(map[string]*zone.Record)
	}
	if active.RecordHistory == nil {
		active.RecordHistory = make(map[string][]*zone.Record)
	}
	for child, delegation := range snapshot.Delegations {
		active.Delegations[child] = cloneDelegation(delegation)
	}
	for child, revocation := range snapshot.Revocations {
		active.Revocations[child] = cloneRevocation(revocation)
		if activeRevocationApplies(active.Delegations[child], revocation) {
			delete(active.Delegations, child)
		}
	}

	var applied int
	for _, record := range orderedSnapshotRecords(snapshot) {
		err := candidate.PutAt(record, now)
		switch {
		case err == nil:
			applied++
		case errors.Is(err, zone.ErrStaleRecord), errors.Is(err, zone.ErrRecordConflict):
			continue
		default:
			return nil, err
		}
	}

	result := &ApplyResult{
		Zone:       snapshot.Zone,
		Records:    applied,
		Delegation: len(active.Delegations),
	}
	*ns = *candidate
	return result, nil
}

func checkSnapshotLimits(snapshot *ZoneSnapshot, limits SyncLimits) error {
	records := countRecords(snapshot.RecordHistory) + len(snapshot.Records)
	if limits.MaxRecords > 0 && records > limits.MaxRecords {
		return ErrZoneSnapshotTooLarge
	}
	if limits.MaxBytes > 0 {
		// Use msgpack for size check because it is the default wire codec.
		data, err := msgpack.Marshal(snapshot)
		if err != nil {
			return err
		}
		if len(data) > limits.MaxBytes {
			return ErrZoneSnapshotTooLarge
		}
	}
	return nil
}

func orderedSnapshotRecords(snapshot *ZoneSnapshot) []*zone.Record {
	byKey := make(map[string][]*zone.Record)
	for key, record := range snapshot.Records {
		if record != nil {
			byKey[key] = append(byKey[key], cloneRecord(record))
		}
	}

	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out []*zone.Record
	for _, key := range keys {
		records := byKey[key]
		sort.SliceStable(records, func(i, j int) bool {
			if records[i].Version == records[j].Version {
				return bytes.Compare(higgscrypto.RecordHash(records[i]), higgscrypto.RecordHash(records[j])) < 0
			}
			return records[i].Version < records[j].Version
		})
		out = append(out, records...)
	}
	return out
}

func snapshotZoneState(snapshot *ZoneSnapshot) *zone.ZoneState {
	return &zone.ZoneState{
		Path:          snapshot.Zone,
		Authority:     cloneAuthority(snapshot.Authority),
		ParentProof:   cloneDelegationSlice(snapshot.ParentProof),
		Delegations:   cloneDelegationMap(snapshot.Delegations),
		Revocations:   cloneRevocationMap(snapshot.Revocations),
		Records:       cloneRecordMap(snapshot.Records),
		RecordHistory: cloneRecordHistory(snapshot.RecordHistory),
	}
}

func snapshotParentProof(ns *zone.NetworkState, path zone.ZonePath, zs *zone.ZoneState) []*zone.Delegation {
	proof := cloneDelegationSlice(zs.ParentProof)
	if path == zone.RootZone || ns == nil {
		return proof
	}
	parent := path.Parent()
	if parent == zone.RootZone {
		return proof
	}
	parentState := ns.Zones[parent]
	if parentState == nil {
		return proof
	}
	delegation := parentState.Delegations[path]
	if delegation == nil {
		return proof
	}
	for _, existing := range proof {
		if existing != nil && existing.ZoneName == path {
			return proof
		}
	}
	return append([]*zone.Delegation{cloneDelegation(delegation)}, proof...)
}

func cloneNetworkState(ns *zone.NetworkState) *zone.NetworkState {
	if ns == nil {
		return zone.NewNetworkState()
	}
	return zone.CloneNetworkState(ns)
}

func countRecords(records map[string][]*zone.Record) int {
	var out int
	for _, list := range records {
		out += len(list)
	}
	return out
}

func cloneRecordMap(records map[string]*zone.Record) map[string]*zone.Record {
	if records == nil {
		return nil
	}
	out := make(map[string]*zone.Record, len(records))
	for key, record := range records {
		out[key] = cloneRecord(record)
	}
	return out
}

func cloneRecordHistory(records map[string][]*zone.Record) map[string][]*zone.Record {
	if records == nil {
		return nil
	}
	out := make(map[string][]*zone.Record, len(records))
	for key, list := range records {
		if list == nil {
			out[key] = nil
			continue
		}
		out[key] = make([]*zone.Record, 0, len(list))
		for _, record := range list {
			out[key] = append(out[key], cloneRecord(record))
		}
	}
	return out
}

func cloneDelegationMap(delegations map[zone.ZonePath]*zone.Delegation) map[zone.ZonePath]*zone.Delegation {
	if delegations == nil {
		return nil
	}
	out := make(map[zone.ZonePath]*zone.Delegation, len(delegations))
	for path, delegation := range delegations {
		out[path] = cloneDelegation(delegation)
	}
	return out
}

func cloneRevocationMap(revocations map[zone.ZonePath]*zone.DelegationRevocation) map[zone.ZonePath]*zone.DelegationRevocation {
	if revocations == nil {
		return nil
	}
	out := make(map[zone.ZonePath]*zone.DelegationRevocation, len(revocations))
	for path, revocation := range revocations {
		out[path] = cloneRevocation(revocation)
	}
	return out
}

func cloneDelegationSlice(delegations []*zone.Delegation) []*zone.Delegation {
	if delegations == nil {
		return nil
	}
	out := make([]*zone.Delegation, 0, len(delegations))
	for _, delegation := range delegations {
		out = append(out, cloneDelegation(delegation))
	}
	return out
}

func cloneAuthority(authority *zone.ZoneAuthority) *zone.ZoneAuthority {
	if authority == nil {
		return nil
	}
	out := *authority
	out.Keys = make([]zone.AuthorizedKey, len(authority.Keys))
	for i, key := range authority.Keys {
		out.Keys[i] = key
		out.Keys[i].Key = cloneBytes(key.Key)
		out.Keys[i].Capabilities = append([]zone.Capability(nil), key.Capabilities...)
		for j := range out.Keys[i].Capabilities {
			out.Keys[i].Capabilities[j].Permissions = append([]zone.Permission(nil), key.Capabilities[j].Permissions...)
		}
	}
	return &out
}

func cloneDelegation(delegation *zone.Delegation) *zone.Delegation {
	if delegation == nil {
		return nil
	}
	out := *delegation
	out.Authority = *cloneAuthority(&delegation.Authority)
	out.AuthorityHash = cloneBytes(delegation.AuthorityHash)
	out.SignedBy = cloneBytes(delegation.SignedBy)
	out.Signature = cloneBytes(delegation.Signature)
	if delegation.ExpiresAt != nil {
		expires := *delegation.ExpiresAt
		out.ExpiresAt = &expires
	}
	return &out
}

func cloneRevocation(revocation *zone.DelegationRevocation) *zone.DelegationRevocation {
	if revocation == nil {
		return nil
	}
	out := *revocation
	out.RevokedAuthorityHash = cloneBytes(revocation.RevokedAuthorityHash)
	out.SignedBy = cloneBytes(revocation.SignedBy)
	out.Signature = cloneBytes(revocation.Signature)
	return &out
}

func activeRevocationApplies(delegation *zone.Delegation, revocation *zone.DelegationRevocation) bool {
	if revocation == nil {
		return false
	}
	if delegation == nil {
		return true
	}
	return bytes.Equal(revocation.RevokedAuthorityHash, delegation.AuthorityHash) || revocation.RevokedAuthorityEpoch >= delegation.AuthorityEpoch
}

func cloneRecord(record *zone.Record) *zone.Record {
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
	if in == nil {
		return nil
	}
	return append([]byte(nil), in...)
}
