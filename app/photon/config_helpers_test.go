package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func writeRuntimeConfig(t *testing.T, path string, dataDir string, rootKey ed25519.PublicKey, extra map[string]string) {
	t.Helper()
	var lines []string
	lines = append(lines, "data_dir: "+dataDir)
	lines = append(lines, "gossip:")
	lines = append(lines, "  listen_addr: 127.0.0.1:0")
	if len(rootKey) > 0 {
		lines = append(lines, "trusted_root_public_key: "+hex.EncodeToString(rootKey))
	}
	for _, key := range []string{"max_datagram_bytes", "max_sync_zones", "max_sync_records"} {
		if value := extra[key]; value != "" {
			lines = append(lines, "  "+key+": "+value)
		}
	}
	if value := extra["log.level"]; value != "" || extra["log.mode"] != "" {
		lines = append(lines, "log:")
		if mode := extra["log.mode"]; mode != "" {
			lines = append(lines, "  mode: "+mode)
			if file := extra["log.file"]; file != "" {
				lines = append(lines, "  file: "+file)
			}
		}
		if value != "" {
			lines = append(lines, "  level: "+value)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config): %v", err)
	}
}
