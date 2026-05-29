package zone

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidZonePath    = errors.New("invalid zone path")
	ErrInvalidFQKey       = errors.New("invalid fully-qualified key")
	ErrZoneNotFound       = errors.New("zone not found")
	ErrRecordNotFound     = errors.New("record not found")
	ErrPendingRecord      = errors.New("record pending predecessor")
	ErrStaleRecord        = errors.New("stale record version")
	ErrRecordConflict     = errors.New("record version conflict")
	ErrInvalidRecordChain = errors.New("invalid record version chain")
)

func ParseFQKey(fqkey string) (ZonePath, string, error) {
	zonePart, key, ok := strings.Cut(fqkey, "/")
	if !ok || key == "" {
		return "", "", ErrInvalidFQKey
	}

	zp := ZonePath(zonePart)
	if !zp.Valid() {
		return "", "", ErrInvalidZonePath
	}

	return zp, key, nil
}

func (ns *NetworkState) Get(fqkey string) (*Record, error) {
	zp, key, err := ParseFQKey(fqkey)
	if err != nil {
		return nil, err
	}

	for _, current := range zp.Ancestors() {
		zs := ns.Zones[current]
		if zs == nil {
			continue
		}
		if r := zs.Records[key]; r != nil {
			return r, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrRecordNotFound, fqkey)
}

func (ns *NetworkState) Put(record *Record) error {
	return ns.PutAt(record, time.Now())
}

func (ns *NetworkState) PutAt(record *Record, now time.Time) error {
	if ns.RecordVerifier == nil && ns.RecordHasher == nil {
		return ns.PutTrusted(record)
	}

	if record == nil {
		return errors.New("record is nil")
	}
	if !record.Zone.Valid() {
		return ErrInvalidZonePath
	}
	if record.Key == "" {
		return ErrInvalidFQKey
	}

	zs := ns.Zones[record.Zone]
	if zs == nil {
		return fmt.Errorf("%w: %s", ErrZoneNotFound, record.Zone)
	}

	if ns.RecordVerifier != nil {
		if err := ns.RecordVerifier(record, zs.Authority, now); err != nil {
			return err
		}
	}

	current := zs.Records[record.Key]
	if current == nil {
		if record.Version != 1 || len(record.PrevHash) != 0 {
			zs.PendingRecords[record.Key] = append(zs.PendingRecords[record.Key], record)
			return ErrPendingRecord
		}
		zs.Records[record.Key] = record
		ns.promotePending(zs, record.Key)
		return nil
	}

	if record.Version < current.Version {
		return ErrStaleRecord
	}
	if record.Version == current.Version {
		if ns.sameRecord(record, current) {
			return nil
		}
		return ErrRecordConflict
	}
	if record.Version != current.Version+1 {
		zs.PendingRecords[record.Key] = append(zs.PendingRecords[record.Key], record)
		return ErrPendingRecord
	}
	if ns.RecordHasher != nil && !equalBytes(record.PrevHash, ns.RecordHasher(current)) {
		zs.PendingRecords[record.Key] = append(zs.PendingRecords[record.Key], record)
		return ErrPendingRecord
	}

	zs.RecordHistory[record.Key] = append(zs.RecordHistory[record.Key], current)
	zs.Records[record.Key] = record
	ns.promotePending(zs, record.Key)
	return nil
}

func (ns *NetworkState) promotePending(zs *ZoneState, key string) {
	if ns.RecordHasher == nil {
		return
	}

	for {
		current := zs.Records[key]
		if current == nil {
			return
		}
		currentHash := ns.RecordHasher(current)
		pending := zs.PendingRecords[key]
		promoted := false
		kept := pending[:0]
		for _, candidate := range pending {
			if candidate.Version == current.Version+1 && equalBytes(candidate.PrevHash, currentHash) {
				zs.RecordHistory[key] = append(zs.RecordHistory[key], current)
				zs.Records[key] = candidate
				promoted = true
				continue
			}
			kept = append(kept, candidate)
		}
		if len(kept) == 0 {
			delete(zs.PendingRecords, key)
		} else {
			zs.PendingRecords[key] = kept
		}
		if !promoted {
			return
		}
	}
}

func (ns *NetworkState) sameRecord(a, b *Record) bool {
	if ns.RecordHasher != nil {
		return equalBytes(ns.RecordHasher(a), ns.RecordHasher(b))
	}
	return a == b
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var out byte
	for i := range a {
		out |= a[i] ^ b[i]
	}
	return out == 0
}

func (ns *NetworkState) PutTrusted(record *Record) error {
	if record == nil {
		return errors.New("record is nil")
	}
	if !record.Zone.Valid() {
		return ErrInvalidZonePath
	}
	if record.Key == "" {
		return ErrInvalidFQKey
	}

	zs := ns.Zones[record.Zone]
	if zs == nil {
		return fmt.Errorf("%w: %s", ErrZoneNotFound, record.Zone)
	}

	current := zs.Records[record.Key]
	if current != nil {
		zs.RecordHistory[record.Key] = append(zs.RecordHistory[record.Key], current)
	}
	zs.Records[record.Key] = record
	return nil
}
