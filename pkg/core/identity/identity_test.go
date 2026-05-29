package identity

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptPrivateKey(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	encrypted, err := EncryptPrivateKey(id.PrivateKey, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}
	if !bytes.Equal(encrypted.NodeID, NodeID(id.PublicKey)) {
		t.Fatalf("encrypted NodeID does not match public key")
	}

	got, err := DecryptPrivateKey(encrypted, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("DecryptPrivateKey: %v", err)
	}
	if !bytes.Equal(got, id.PrivateKey) {
		t.Fatalf("decrypted private key mismatch")
	}

	if _, err := DecryptPrivateKey(encrypted, []byte("wrong")); err == nil {
		t.Fatalf("DecryptPrivateKey accepted wrong passphrase")
	}
}

func TestSaveLoadEncryptedPrivateKey(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "identity.json")

	if err := SaveEncryptedPrivateKey(path, id.PrivateKey, []byte("phase0")); err != nil {
		t.Fatalf("SaveEncryptedPrivateKey: %v", err)
	}
	got, err := LoadEncryptedPrivateKey(path, []byte("phase0"))
	if err != nil {
		t.Fatalf("LoadEncryptedPrivateKey: %v", err)
	}
	if !bytes.Equal(got, id.PrivateKey) {
		t.Fatalf("loaded private key mismatch")
	}
}
