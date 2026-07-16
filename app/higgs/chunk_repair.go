package main

import (
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Catofes/higgs/pkg/core/gossip"
)

const (
	chunkRepairQuiet       = 150 * time.Millisecond
	chunkTransferTTL       = 30 * time.Second
	maxChunkRepairRounds   = 3
	maxChunkNACKIndexes    = 128
	maxChunkPeerInflight   = 4
	maxChunkSendCacheBytes = 32 << 20
)

type sentChunkTransfer struct {
	peerID       string
	transferID   []byte
	chunks       []*gossip.ObjectChunk
	bytes        int
	created      time.Time
	expires      time.Time
	repairRounds int
	lastRequest  string
}

type sentChunkCache struct {
	mu      sync.Mutex
	entries map[string]*sentChunkTransfer
	bytes   int
}

func newSentChunkCache() *sentChunkCache {
	return &sentChunkCache{entries: make(map[string]*sentChunkTransfer)}
}

func sentTransferKey(peerID string, transferID []byte) string {
	return peerID + "|" + hex.EncodeToString(transferID)
}

func (c *sentChunkCache) put(peerID string, transferID []byte, chunks []*gossip.ObjectChunk, now time.Time) bool {
	if c == nil || peerID == "" || len(transferID) != 16 || len(chunks) == 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	peerCount := 0
	for _, entry := range c.entries {
		if entry.peerID == peerID {
			peerCount++
		}
	}
	if peerCount >= maxChunkPeerInflight {
		return false
	}
	entry := &sentChunkTransfer{peerID: peerID, transferID: append([]byte(nil), transferID...), created: now, expires: now.Add(chunkTransferTTL)}
	for _, chunk := range chunks {
		if chunk == nil {
			continue
		}
		copyChunk := *chunk
		copyChunk.TransferID = append([]byte(nil), chunk.TransferID...)
		copyChunk.RootHash = append([]byte(nil), chunk.RootHash...)
		copyChunk.ObjectHash = append([]byte(nil), chunk.ObjectHash...)
		copyChunk.Data = append([]byte(nil), chunk.Data...)
		entry.bytes += len(copyChunk.Data)
		entry.chunks = append(entry.chunks, &copyChunk)
	}
	if entry.bytes == 0 || entry.bytes > maxChunkSendCacheBytes || c.bytes+entry.bytes > maxChunkSendCacheBytes {
		return false
	}
	key := sentTransferKey(peerID, transferID)
	c.entries[key] = entry
	c.bytes += entry.bytes
	return true
}

func (c *sentChunkCache) repair(peerID string, nack *gossip.ObjectChunkNACK, now time.Time) []*gossip.ObjectChunk {
	if c == nil || nack == nil || len(nack.Missing) == 0 || len(nack.Missing) > maxChunkNACKIndexes {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	entry := c.entries[sentTransferKey(peerID, nack.TransferID)]
	if entry == nil || entry.repairRounds >= maxChunkRepairRounds {
		return nil
	}
	indexes := append([]uint16(nil), nack.Missing...)
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
	parts := make([]string, 0, len(indexes))
	for _, index := range indexes {
		parts = append(parts, string(rune(index)))
	}
	signature := strings.Join(parts, ",")
	if signature == entry.lastRequest {
		return nil
	}
	entry.lastRequest = signature
	entry.repairRounds++
	result := make([]*gossip.ObjectChunk, 0, len(indexes))
	for _, index := range indexes {
		if int(index) >= len(entry.chunks) || entry.chunks[index] == nil {
			continue
		}
		chunk := *entry.chunks[index]
		chunk.Data = append([]byte(nil), chunk.Data...)
		result = append(result, &chunk)
	}
	return result
}

func (c *sentChunkCache) pruneLocked(now time.Time) {
	for key, entry := range c.entries {
		if entry == nil || !entry.expires.After(now) {
			if entry != nil {
				c.bytes -= entry.bytes
			}
			delete(c.entries, key)
		}
	}
}

func missingChunkIndexes(chunks [][]byte, limit int) []uint16 {
	if limit <= 0 || limit > maxChunkNACKIndexes {
		limit = maxChunkNACKIndexes
	}
	missing := make([]uint16, 0)
	for index, chunk := range chunks {
		if chunk == nil {
			missing = append(missing, uint16(index))
			if len(missing) == limit {
				break
			}
		}
	}
	return missing
}

var udpSentChunkCache = newSentChunkCache()
