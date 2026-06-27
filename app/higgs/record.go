package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
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

func getRecord(path zone.ZonePath, key string, history int) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	if history < 0 {
		return fmt.Errorf("history must be >= 0")
	}
	if record, ok, err := getRecordViaControl(rt, path, key, history); ok {
		if err != nil {
			return err
		}
		return writeRecordJSON(record)
	}
	logControlFallback("record_get")
	return getRecordDirect(rt, path, key, history)
}

func getRecordDirect(rt *Runtime, path zone.ZonePath, key string, history int) error {
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	record, err := lookupRecordJSON(state, path, key, history)
	if err != nil {
		return err
	}
	return writeRecordJSON(record)
}

func lookupRecordJSON(state *stateFile, path zone.ZonePath, key string, history int) (map[string]any, error) {
	if history < 0 {
		return nil, fmt.Errorf("history must be >= 0")
	}
	if state == nil || state.Network == nil {
		return nil, fmt.Errorf("state is nil")
	}
	zs := state.Network.Zones[path]
	if zs == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	rec := zs.Records[key]
	if rec == nil {
		return nil, fmt.Errorf("record not found: %s/%s", path, key)
	}
	out := recordJSON(rec, len(zs.RecordHistory[key]))
	if history > 0 {
		out["record_history"] = recordHistoryJSON(zs.RecordHistory[key], history)
	}
	return out, nil
}

func recordHistoryJSON(records []*zone.Record, limit int) []map[string]any {
	if limit <= 0 {
		return nil
	}
	out := make([]map[string]any, 0, limit)
	if len(records) == 0 {
		return out
	}
	if limit > len(records) {
		limit = len(records)
	}
	for i := len(records) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, recordJSON(records[i], 0))
	}
	return out
}

func writeRecordJSON(record map[string]any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(record)
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
