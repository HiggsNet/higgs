package gossip

import (
	"errors"
	"time"
)

var ErrQuotaExceeded = errors.New("gossip peer quota exceeded")

type QuotaConfig struct {
	ByteRate    int64
	ByteBurst   int64
	ObjectRate  int64
	ObjectBurst int64
}

type PeerQuotas struct {
	config QuotaConfig
	peers  map[string]*quotaBucket
}

type quotaBucket struct {
	bytes   int64
	objects int64
	last    time.Time
}

func NewPeerQuotas(config QuotaConfig) *PeerQuotas {
	if config.ByteRate <= 0 {
		config.ByteRate = 256 << 10
	}
	if config.ByteBurst <= 0 {
		config.ByteBurst = config.ByteRate
	}
	if config.ObjectRate <= 0 {
		config.ObjectRate = 128
	}
	if config.ObjectBurst <= 0 {
		config.ObjectBurst = config.ObjectRate
	}
	return &PeerQuotas{
		config: config,
		peers:  make(map[string]*quotaBucket),
	}
}

func (pq *PeerQuotas) Allow(peerID string, bytes int64, objects int64, now time.Time) error {
	if pq == nil {
		return nil
	}
	if bytes < 0 || objects < 0 {
		return ErrQuotaExceeded
	}
	bucket := pq.peers[peerID]
	if bucket == nil {
		bucket = &quotaBucket{
			bytes:   pq.config.ByteBurst,
			objects: pq.config.ObjectBurst,
			last:    now,
		}
		pq.peers[peerID] = bucket
	}
	pq.refill(bucket, now)
	if bytes > bucket.bytes || objects > bucket.objects {
		return ErrQuotaExceeded
	}
	bucket.bytes -= bytes
	bucket.objects -= objects
	return nil
}

func (pq *PeerQuotas) refill(bucket *quotaBucket, now time.Time) {
	if now.Before(bucket.last) {
		bucket.last = now
		return
	}
	elapsed := now.Sub(bucket.last).Seconds()
	bucket.bytes = minInt64(pq.config.ByteBurst, bucket.bytes+int64(elapsed*float64(pq.config.ByteRate)))
	bucket.objects = minInt64(pq.config.ObjectBurst, bucket.objects+int64(elapsed*float64(pq.config.ObjectRate)))
	bucket.last = now
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
