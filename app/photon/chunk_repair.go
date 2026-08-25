package main

import "github.com/HiggsNet/photon/pkg/core/gossip"

// Compatibility constructors keep Linux tests and globals stable while all
// assembly and repair policy lives in the shared gossip package.
func newChunkAssemblyStore() *gossip.ChunkAssemblyStore {
	return gossip.NewChunkAssemblyStore()
}

func newSentChunkCache() *gossip.SentChunkCache {
	return gossip.NewSentChunkCache()
}

var udpSentChunkCache = newSentChunkCache()
