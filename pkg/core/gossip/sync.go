package gossip

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"time"

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
	Pending    int
	Delegation int
}

func DefaultSyncLimits() SyncLimits {
	return SyncLimits{
		MaxZones:   16,
		MaxRecords: 1024,
		MaxBytes:   DefaultMaxMessage,
	}
}

func FetchList(local *zone.NetworkState, remote []ZoneDigest) []zone.ZonePath {
	localByZone := make(map[zone.ZonePath][]byte)
	for _, digest := range ZoneDigests(local) {
		localByZone[digest.Zone] = digest.RootHash
	}

	var out []zone.ZonePath
	for _, digest := range remote {
		if !digest.Zone.Valid() {
			continue
		}
		if !bytes.Equal(localByZone[digest.Zone], digest.RootHash) {
			out = append(out, digest.Zone)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
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
		Zone:           path,
		Authority:      cloneAuthority(zs.Authority),
		ParentProof:    cloneDelegationSlice(zs.ParentProof),
		Delegations:    cloneDelegationMap(zs.Delegations),
		Records:        cloneRecordMap(zs.Records),
		RecordHistory:  cloneRecordHistory(zs.RecordHistory),
		PendingRecords: cloneRecordHistory(zs.PendingRecords),
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
	for _, record := range zs.PendingRecords[fetch.Key] {
		if record != nil && (fetch.Version == 0 || record.Version == fetch.Version) {
			return &RecordSnapshot{Zone: fetch.Zone, Record: cloneRecord(record)}, nil
		}
	}
	return nil, fmt.Errorf("%w: %s/%s", zone.ErrRecordNotFound, fetch.Zone, fetch.Key)
}

func ApplyRecordSnapshot(ns *zone.NetworkState, snapshot *RecordSnapshot, now time.Time) error {
	if ns == nil {
		return errors.New("network state is nil")
	}
	if snapshot == nil || snapshot.Record == nil {
		return errors.New("record snapshot is nil")
	}
	if snapshot.Zone != snapshot.Record.Zone {
		return zone.ErrInvalidZonePath
	}
	ns.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
	if err := higgscrypto.VerifyChain(ns, snapshot.Zone, now); err != nil {
		return fmt.Errorf("%w: %v", ErrUntrustedZone, err)
	}
	return ns.PutAt(cloneRecord(snapshot.Record), now)
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
	if limits == (SyncLimits{}) {
		limits = DefaultSyncLimits()
	}
	if err := checkSnapshotLimits(snapshot, limits); err != nil {
		return nil, err
	}

	candidate := cloneNetworkState(ns)
	candidate.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
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

	active := ns.Zones[snapshot.Zone]
	if active == nil {
		active = zone.NewZoneState(snapshot.Zone, cloneAuthority(snapshot.Authority))
		ns.Zones[snapshot.Zone] = active
	} else {
		active.Authority = cloneAuthority(snapshot.Authority)
	}
	active.ParentProof = cloneDelegationSlice(snapshot.ParentProof)
	if active.Delegations == nil {
		active.Delegations = make(map[zone.ZonePath]*zone.Delegation)
	}
	if active.Records == nil {
		active.Records = make(map[string]*zone.Record)
	}
	if active.RecordHistory == nil {
		active.RecordHistory = make(map[string][]*zone.Record)
	}
	if active.PendingRecords == nil {
		active.PendingRecords = make(map[string][]*zone.Record)
	}
	for child, delegation := range snapshot.Delegations {
		active.Delegations[child] = cloneDelegation(delegation)
	}

	ns.ConfigureRecordValidation(higgscrypto.VerifyRecord, higgscrypto.RecordHash)
	var applied, pending int
	for _, record := range orderedSnapshotRecords(snapshot) {
		err := ns.PutAt(record, now)
		switch {
		case err == nil:
			applied++
		case errors.Is(err, zone.ErrPendingRecord):
			pending++
		case errors.Is(err, zone.ErrStaleRecord), errors.Is(err, zone.ErrRecordConflict):
			continue
		default:
			return nil, err
		}
	}

	return &ApplyResult{
		Zone:       snapshot.Zone,
		Records:    applied,
		Pending:    pending + countRecords(active.PendingRecords),
		Delegation: len(active.Delegations),
	}, nil
}

func checkSnapshotLimits(snapshot *ZoneSnapshot, limits SyncLimits) error {
	records := countRecords(snapshot.RecordHistory) + len(snapshot.Records) + countRecords(snapshot.PendingRecords)
	if limits.MaxRecords > 0 && records > limits.MaxRecords {
		return ErrZoneSnapshotTooLarge
	}
	return nil
}

func orderedSnapshotRecords(snapshot *ZoneSnapshot) []*zone.Record {
	byKey := make(map[string][]*zone.Record)
	for key, history := range snapshot.RecordHistory {
		for _, record := range history {
			if record != nil {
				byKey[key] = append(byKey[key], cloneRecord(record))
			}
		}
	}
	for key, record := range snapshot.Records {
		if record != nil {
			byKey[key] = append(byKey[key], cloneRecord(record))
		}
	}
	for key, pending := range snapshot.PendingRecords {
		for _, record := range pending {
			if record != nil {
				byKey[key] = append(byKey[key], cloneRecord(record))
			}
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
		Path:           snapshot.Zone,
		Authority:      cloneAuthority(snapshot.Authority),
		ParentProof:    cloneDelegationSlice(snapshot.ParentProof),
		Delegations:    cloneDelegationMap(snapshot.Delegations),
		Records:        cloneRecordMap(snapshot.Records),
		RecordHistory:  cloneRecordHistory(snapshot.RecordHistory),
		PendingRecords: cloneRecordHistory(snapshot.PendingRecords),
	}
}

func cloneNetworkState(ns *zone.NetworkState) *zone.NetworkState {
	out := zone.NewNetworkState()
	if ns == nil {
		return out
	}
	for path, zs := range ns.Zones {
		if zs == nil {
			continue
		}
		out.Zones[path] = &zone.ZoneState{
			Path:           zs.Path,
			Authority:      cloneAuthority(zs.Authority),
			ParentProof:    cloneDelegationSlice(zs.ParentProof),
			Delegations:    cloneDelegationMap(zs.Delegations),
			Records:        cloneRecordMap(zs.Records),
			RecordHistory:  cloneRecordHistory(zs.RecordHistory),
			PendingRecords: cloneRecordHistory(zs.PendingRecords),
			MerkleRoot:     cloneBytes(zs.MerkleRoot),
		}
	}
	out.GlobalRoot = cloneBytes(ns.GlobalRoot)
	return out
}

func countRecords(records map[string][]*zone.Record) int {
	var out int
	for _, list := range records {
		out += len(list)
	}
	return out
}

func cloneRecordMap(records map[string]*zone.Record) map[string]*zone.Record {
	out := make(map[string]*zone.Record, len(records))
	for key, record := range records {
		out[key] = cloneRecord(record)
	}
	return out
}

func cloneRecordHistory(records map[string][]*zone.Record) map[string][]*zone.Record {
	out := make(map[string][]*zone.Record, len(records))
	for key, list := range records {
		for _, record := range list {
			out[key] = append(out[key], cloneRecord(record))
		}
	}
	return out
}

func cloneDelegationMap(delegations map[zone.ZonePath]*zone.Delegation) map[zone.ZonePath]*zone.Delegation {
	out := make(map[zone.ZonePath]*zone.Delegation, len(delegations))
	for path, delegation := range delegations {
		out[path] = cloneDelegation(delegation)
	}
	return out
}

func cloneDelegationSlice(delegations []*zone.Delegation) []*zone.Delegation {
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
