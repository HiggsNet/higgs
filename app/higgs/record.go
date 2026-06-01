package main

import (
	"fmt"
	"time"

	"github.com/Catofes/higgs/pkg/core/zone"
	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

func putRecord(path zone.ZonePath, key string, value []byte, recordType string) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	record, err := buildSignedRecord(state, path, key, value, recordType)
	if err != nil {
		return err
	}
	if err := state.Network.Put(record); err != nil {
		return err
	}
	if err := saveState(state); err != nil {
		return err
	}
	fmt.Printf("put %s/%s version %d\n", path, key, record.Version)
	return nil
}

func buildSignedRecord(state *stateFile, path zone.ZonePath, key string, value []byte, recordType string) (*zone.Record, error) {
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
		Timestamp: time.Now().Unix(),
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
