package main

import (
	"fmt"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func putRecord(path zone.ZonePath, key string, value []byte, recordType string) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	record, err := buildSignedRecordAt(state, path, key, value, recordType, rt.Now())
	if err != nil {
		return err
	}
	if err := state.Network.Put(record); err != nil {
		return err
	}
	if err := rt.SaveState(state); err != nil {
		return err
	}
	fmt.Printf("put %s/%s version %d\n", path, key, record.Version)
	return nil
}

func buildSignedRecord(state *stateFile, path zone.ZonePath, key string, value []byte, recordType string) (*zone.Record, error) {
	return buildSignedRecordAt(state, path, key, value, recordType, timeNow())
}

func buildSignedRecordAt(state *stateFile, path zone.ZonePath, key string, value []byte, recordType string, now time.Time) (*zone.Record, error) {
	configureValidation(state.Network)
	zs := state.Network.Zones[path]
	if zs == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	current := zs.Records[key]
	record := &zone.Record{
		Zone:      path,
		Key:       key,
		Type:      recordType,
		Value:     value,
		Version:   1,
		Timestamp: now.Unix(),
	}
	if current != nil {
		record.Version = current.Version + 1
		record.PrevHash = higgscrypto.RecordHash(current)
	}
	if err := higgscrypto.SignRecord(record, state.ZonePrivateKey); err != nil {
		return nil, err
	}
	return record, nil
}
