package zone

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidZonePath = errors.New("invalid zone path")
	ErrInvalidFQKey    = errors.New("invalid fully-qualified key")
	ErrZoneNotFound    = errors.New("zone not found")
	ErrRecordNotFound  = errors.New("record not found")
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
