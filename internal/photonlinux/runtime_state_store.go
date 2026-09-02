package photonlinux

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	bolt "go.etcd.io/bbolt"
)

const (
	runtimeStateSchemaVersion uint64 = 1
	RuntimeStateBucketName           = "photon:linux-runtime"
)

var (
	runtimeStateBucket                    = []byte(RuntimeStateBucketName)
	runtimeStateSchemaKey                 = []byte("schema-version")
	runtimeStatePayloadKey                = []byte("payload")
	ErrRuntimeStateCorrupt                = errors.New("linux runtime state is corrupt")
	ErrRuntimeStateSourceRevisionMismatch = errors.New("runtime state source verified revision does not match current state")
)

// LoadRuntimeStateTx reads the Linux partition from a platform-owned Bolt
// transaction. Missing state is distinct from malformed state.
func LoadRuntimeStateTx(tx *bolt.Tx) (*RuntimeState, bool, error) {
	if tx == nil {
		return nil, false, errors.New("linux runtime load transaction is nil")
	}
	bucket := tx.Bucket(runtimeStateBucket)
	if bucket == nil {
		return nil, false, nil
	}
	version := bucket.Get(runtimeStateSchemaKey)
	if len(version) != 8 || binary.BigEndian.Uint64(version) != runtimeStateSchemaVersion {
		return nil, true, fmt.Errorf("%w: unsupported schema", ErrRuntimeStateCorrupt)
	}
	payload := bucket.Get(runtimeStatePayloadKey)
	if payload == nil {
		return nil, true, fmt.Errorf("%w: payload is missing", ErrRuntimeStateCorrupt)
	}
	if bytes.Equal(bytes.TrimSpace(payload), []byte("null")) {
		return nil, true, fmt.Errorf("%w: payload is null", ErrRuntimeStateCorrupt)
	}
	var state RuntimeState
	if err := json.Unmarshal(payload, &state); err != nil {
		return nil, true, fmt.Errorf("%w: %v", ErrRuntimeStateCorrupt, err)
	}
	return &state, true, nil
}

// SaveRuntimeStateTx writes a byte-level no-op-aware Linux partition through
// a transaction owned by the process composition root.
func SaveRuntimeStateTx(tx *bolt.Tx, state *RuntimeState) (bool, error) {
	if tx == nil || !tx.Writable() {
		return false, errors.New("linux runtime save requires a writable bbolt transaction")
	}
	if state == nil {
		return false, errors.New("linux runtime state is nil")
	}
	bucket, err := tx.CreateBucketIfNotExists(runtimeStateBucket)
	if err != nil {
		return false, err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return false, err
	}
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], runtimeStateSchemaVersion)
	changed := false
	for _, item := range []struct{ key, value []byte }{
		{runtimeStateSchemaKey, version[:]},
		{runtimeStatePayloadKey, payload},
	} {
		if bytes.Equal(bucket.Get(item.key), item.value) {
			continue
		}
		if err := bucket.Put(item.key, item.value); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, nil
}

// CommitRuntimeState persists a Linux completion only when the common
// verified revision still matches the revision used to plan it.
func CommitRuntimeState(store *corestate.BoltStore, sourceRevision corestate.VerifiedRevision, state *RuntimeState) error {
	if store == nil {
		return errors.New("bbolt state store is nil")
	}
	return store.Update(func(tx *bolt.Tx) (bool, error) {
		_, currentRevision, _, found, err := corestate.LoadBoltState(tx)
		if err != nil {
			return false, err
		}
		if !found {
			return false, errors.New("common state is not initialized")
		}
		if sourceRevision != currentRevision {
			return false, fmt.Errorf("%w: completion=%d current=%d", ErrRuntimeStateSourceRevisionMismatch, sourceRevision, currentRevision)
		}
		return SaveRuntimeStateTx(tx, state)
	})
}
