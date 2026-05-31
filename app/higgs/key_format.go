package main

import (
	"crypto/ed25519"
	"encoding/base64"
)

func formatPublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}
