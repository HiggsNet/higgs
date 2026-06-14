package main

import (
	"crypto/ed25519"
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
	if version, ok, err := putRecordViaControl(rt, path, key, value, recordType); ok {
		if err != nil {
			return err
		}
		fmt.Printf("put %s/%s version %d via daemon\n", path, key, version)
		return nil
	}
	logControlFallback("record_put")
	return putRecordDirect(rt, path, key, value, recordType)
}

func putRecordDirect(rt *Runtime, path zone.ZonePath, key string, value []byte, recordType string) error {
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
	signer, err := signingKeyForZone(state, path)
	if err != nil {
		return nil, err
	}
	if err := higgscrypto.SignRecord(record, signer); err != nil {
		return nil, err
	}
	return record, nil
}

func signingKeyForZone(state *stateFile, path zone.ZonePath) (ed25519.PrivateKey, error) {
	if state == nil || state.Network == nil {
		return nil, fmt.Errorf("state is nil")
	}
	zs := state.Network.Zones[path]
	if zs == nil || zs.Authority == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	if len(state.RootPrivateKey) == ed25519.PrivateKeySize && authorityHasPrivateKey(zs.Authority, state.RootPrivateKey) {
		return state.RootPrivateKey, nil
	}
	if len(state.ZonePrivateKey) == ed25519.PrivateKeySize && authorityHasPrivateKey(zs.Authority, state.ZonePrivateKey) {
		return state.ZonePrivateKey, nil
	}
	return nil, fmt.Errorf("no local signing key for zone %s", path)
}

func authorityHasPrivateKey(authority *zone.ZoneAuthority, priv ed25519.PrivateKey) bool {
	if authority == nil || len(priv) != ed25519.PrivateKeySize {
		return false
	}
	pub := priv.Public().(ed25519.PublicKey)
	return authorityHasKey(authority, pub)
}
