package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
)

const (
	encryptedPrivateKeyVersion = 1
	saltSize                   = 16
	nonceSize                  = 12
)

type NodeIdentity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	NodeID     []byte
}

type EncryptedPrivateKey struct {
	Version   int    `json:"version"`
	PublicKey []byte `json:"public_key"`
	NodeID    []byte `json:"node_id"`
	Salt      []byte `json:"salt"`
	Nonce     []byte `json:"nonce"`
	Bcrypt    []byte `json:"bcrypt"`
	Key       []byte `json:"key"`
}

func Generate() (*NodeIdentity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return FromPrivateKey(priv)
}

func FromPrivateKey(privateKey ed25519.PrivateKey) (*NodeIdentity, error) {
	if l := len(privateKey); l != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: %d", l)
	}
	pub := privateKey.Public().(ed25519.PublicKey)
	return &NodeIdentity{
		PrivateKey: privateKey,
		PublicKey:  pub,
		NodeID:     NodeID(pub),
	}, nil
}

func NodeID(publicKey ed25519.PublicKey) []byte {
	sum := blake2b.Sum256(publicKey)
	return sum[:]
}

func EncryptPrivateKey(privateKey ed25519.PrivateKey, passphrase []byte) (*EncryptedPrivateKey, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase is empty")
	}
	id, err := FromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	bcryptHash, err := bcrypt.GenerateFromPassword(passphrase, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(passphrase, salt)
	if err != nil {
		return nil, err
	}

	return &EncryptedPrivateKey{
		Version:   encryptedPrivateKeyVersion,
		PublicKey: append([]byte(nil), id.PublicKey...),
		NodeID:    append([]byte(nil), id.NodeID...),
		Salt:      salt,
		Nonce:     nonce,
		Bcrypt:    bcryptHash,
		Key:       aead.Seal(nil, nonce, privateKey, id.PublicKey),
	}, nil
}

func DecryptPrivateKey(encrypted *EncryptedPrivateKey, passphrase []byte) (ed25519.PrivateKey, error) {
	if encrypted == nil {
		return nil, errors.New("encrypted private key is nil")
	}
	if encrypted.Version != encryptedPrivateKeyVersion {
		return nil, fmt.Errorf("unsupported encrypted private key version: %d", encrypted.Version)
	}
	if err := bcrypt.CompareHashAndPassword(encrypted.Bcrypt, passphrase); err != nil {
		return nil, errors.New("passphrase verification failed")
	}
	aead, err := newAEAD(passphrase, encrypted.Salt)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, encrypted.Nonce, encrypted.Key, encrypted.PublicKey)
	if err != nil {
		return nil, errors.New("private key decrypt failed")
	}
	privateKey := ed25519.PrivateKey(plain)
	id, err := FromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	if !equalBytes(id.PublicKey, encrypted.PublicKey) || !equalBytes(id.NodeID, encrypted.NodeID) {
		return nil, errors.New("private key identity mismatch")
	}
	return privateKey, nil
}

func SaveEncryptedPrivateKey(path string, privateKey ed25519.PrivateKey, passphrase []byte) error {
	encrypted, err := EncryptPrivateKey(privateKey, passphrase)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(encrypted, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func LoadEncryptedPrivateKey(path string, passphrase []byte) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var encrypted EncryptedPrivateKey
	if err := json.Unmarshal(data, &encrypted); err != nil {
		return nil, err
	}
	return DecryptPrivateKey(&encrypted, passphrase)
}

func newAEAD(passphrase, salt []byte) (cipher.AEAD, error) {
	keyMaterial := make([]byte, 0, len(passphrase)+len(salt))
	keyMaterial = append(keyMaterial, passphrase...)
	keyMaterial = append(keyMaterial, salt...)
	key := sha256.Sum256(keyMaterial)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var out byte
	for i := range a {
		out |= a[i] ^ b[i]
	}
	return out == 0
}
