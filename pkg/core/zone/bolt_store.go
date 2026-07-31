package zone

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketMeta       = []byte("_meta")
	metaGlobalRoot   = []byte("global_root")
	keyAuthority     = []byte("authority")
	keyParentProof   = []byte("parent_proof")
	keyDelegations   = []byte("delegations")
	keyRevocations   = []byte("revocations")
	keyRecords       = []byte("records")
	keyRecordHistory = []byte("record_history")
	keyMerkleRoot    = []byte("merkle_root")
)

type BoltStore struct {
	db *bolt.DB
}

func OpenBoltStore(path string, mode os.FileMode) (*BoltStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, mode, nil)
	if err != nil {
		return nil, err
	}
	return &BoltStore{db: db}, nil
}

func (s *BoltStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *BoltStore) SaveNetwork(ns *NetworkState) error {
	if s == nil || s.db == nil {
		return errors.New("bolt store is closed")
	}
	if ns == nil {
		return errors.New("network state is nil")
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(bucketMeta)
		if err != nil {
			return err
		}
		if err := putJSON(meta, metaGlobalRoot, ns.GlobalRoot); err != nil {
			return err
		}

		var staleBuckets [][]byte
		if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			path, ok := parseZoneBucket(name)
			if !ok {
				return nil
			}
			if ns.Zones[path] == nil {
				staleBuckets = append(staleBuckets, append([]byte(nil), name...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, name := range staleBuckets {
			if err := tx.DeleteBucket(name); err != nil {
				return err
			}
		}

		for path, zs := range ns.Zones {
			if zs == nil {
				continue
			}
			bucket, err := tx.CreateBucketIfNotExists(zoneBucket(path))
			if err != nil {
				return err
			}
			if err := putJSON(bucket, keyAuthority, zs.Authority); err != nil {
				return err
			}
			if err := putJSON(bucket, keyParentProof, zs.ParentProof); err != nil {
				return err
			}
			if err := putJSON(bucket, keyDelegations, zs.Delegations); err != nil {
				return err
			}
			if err := putJSON(bucket, keyRevocations, zs.Revocations); err != nil {
				return err
			}
			if err := putJSON(bucket, keyRecords, zs.Records); err != nil {
				return err
			}
			if err := putJSON(bucket, keyRecordHistory, zs.RecordHistory); err != nil {
				return err
			}
			if err := putJSON(bucket, keyMerkleRoot, zs.MerkleRoot); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *BoltStore) SaveMetaJSON(key string, value any) error {
	if s == nil || s.db == nil {
		return errors.New("bolt store is closed")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketMeta)
		if err != nil {
			return err
		}
		return putJSON(bucket, []byte(key), value)
	})
}

func (s *BoltStore) LoadMetaJSON(key string, out any) error {
	if s == nil || s.db == nil {
		return errors.New("bolt store is closed")
	}
	return s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketMeta)
		if bucket == nil {
			return nil
		}
		return getJSON(bucket, []byte(key), out)
	})
}

func (s *BoltStore) LoadNetwork() (*NetworkState, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("bolt store is closed")
	}

	ns := NewNetworkState()
	err := s.db.View(func(tx *bolt.Tx) error {
		if meta := tx.Bucket(bucketMeta); meta != nil {
			if err := getJSON(meta, metaGlobalRoot, &ns.GlobalRoot); err != nil {
				return err
			}
		}

		return tx.ForEach(func(name []byte, bucket *bolt.Bucket) error {
			path, ok := parseZoneBucket(name)
			if !ok {
				return nil
			}
			zs := NewZoneState(path, nil)
			if err := getJSON(bucket, keyAuthority, &zs.Authority); err != nil {
				return err
			}
			if err := getJSON(bucket, keyParentProof, &zs.ParentProof); err != nil {
				return err
			}
			if err := getJSON(bucket, keyDelegations, &zs.Delegations); err != nil {
				return err
			}
			if err := getJSON(bucket, keyRevocations, &zs.Revocations); err != nil {
				return err
			}
			if err := getJSON(bucket, keyRecords, &zs.Records); err != nil {
				return err
			}
			if err := getJSON(bucket, keyRecordHistory, &zs.RecordHistory); err != nil {
				return err
			}
			if err := getJSON(bucket, keyMerkleRoot, &zs.MerkleRoot); err != nil {
				return err
			}
			normalizeZoneState(zs)
			ns.Zones[path] = zs
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return ns, nil
}

func zoneBucket(path ZonePath) []byte {
	return []byte("zone:" + path.String())
}

func parseZoneBucket(name []byte) (ZonePath, bool) {
	const prefix = "zone:"
	if len(name) <= len(prefix) || string(name[:len(prefix)]) != prefix {
		return "", false
	}
	path := ZonePath(string(name[len(prefix):]))
	return path, path.Valid()
}

func putJSON(bucket *bolt.Bucket, key []byte, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return bucket.Put(key, data)
}

func getJSON(bucket *bolt.Bucket, key []byte, out any) error {
	data := bucket.Get(key)
	if data == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: %w", string(key), err)
	}
	return nil
}

func normalizeZoneState(zs *ZoneState) {
	if zs.Delegations == nil {
		zs.Delegations = make(map[ZonePath]*Delegation)
	}
	if zs.Revocations == nil {
		zs.Revocations = make(map[ZonePath]*DelegationRevocation)
	}
	if zs.Records == nil {
		zs.Records = make(map[string]*Record)
	}
	if zs.RecordHistory == nil {
		zs.RecordHistory = make(map[string][]*Record)
		return
	}
	for key, history := range zs.RecordHistory {
		zs.RecordHistory[key] = boundRecordHistory(history)
	}
}
