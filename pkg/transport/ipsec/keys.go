package ipsec

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	higgscrypto "github.com/Catofes/higgs/pkg/crypto"
)

type TransportPrivateKey struct {
	Kind       string
	Algorithm  string
	PublicKey  []byte
	PrivateKey []byte
}

func GenerateTransportKeyRecord(algorithm string, now time.Time, validFor time.Duration, forbiddenPublicKeys ...[]byte) (*TransportPrivateKey, *TransportKeyRecord, error) {
	if algorithm == "" {
		algorithm = AlgorithmEd25519
	}
	key, err := generateTransportPrivateKey(algorithm)
	if err != nil {
		return nil, nil, err
	}
	record, err := NewTransportKeyRecord(algorithm, key.PublicKey, now, validFor, forbiddenPublicKeys...)
	if err != nil {
		return nil, nil, err
	}
	return key, record, nil
}

func NewTransportKeyRecord(algorithm string, publicKey []byte, now time.Time, validFor time.Duration, forbiddenPublicKeys ...[]byte) (*TransportKeyRecord, error) {
	if algorithm == "" {
		algorithm = AlgorithmEd25519
	}
	if !oneOf(algorithm, AlgorithmEd25519, AlgorithmECDSAP256) {
		return nil, fmt.Errorf("unsupported transport key algorithm %q", algorithm)
	}
	if len(publicKey) == 0 {
		return nil, fmt.Errorf("transport public key is required")
	}
	for _, forbidden := range forbiddenPublicKeys {
		if len(forbidden) > 0 && bytes.Equal(publicKey, forbidden) {
			return nil, fmt.Errorf("transport key must not reuse a zone signing key")
		}
	}
	record := &TransportKeyRecord{
		Version:     1,
		Kind:        TransportKeyRawPublicKey,
		Algorithm:   algorithm,
		PublicKey:   base64.StdEncoding.EncodeToString(publicKey),
		Fingerprint: TransportKeyFingerprint(algorithm, publicKey),
		NotBefore:   now.Unix(),
		UpdatedAt:   now.Unix(),
	}
	if validFor > 0 {
		record.NotAfter = now.Add(validFor).Unix()
	}
	return record, nil
}

func DecodeTransportPublicKey(record TransportKeyRecord) ([]byte, error) {
	if record.PublicKey == "" {
		return nil, fmt.Errorf("public_key is required")
	}
	publicKey, err := base64.StdEncoding.DecodeString(record.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode transport public key: %w", err)
	}
	if len(publicKey) == 0 {
		return nil, fmt.Errorf("transport public key is empty")
	}
	if record.Fingerprint != "" {
		want := TransportKeyFingerprint(record.Algorithm, publicKey)
		if record.Fingerprint != want {
			return nil, fmt.Errorf("transport key fingerprint mismatch")
		}
	}
	return publicKey, nil
}

func TransportKeyFingerprint(algorithm string, publicKey []byte) string {
	sum := higgscrypto.Hash([]byte("higgs.ipsec.transport-key.v1"), []byte{0}, []byte(algorithm), []byte{0}, publicKey)
	encoded := hex.EncodeToString(sum)
	parts := make([]string, 0, len(encoded)/2)
	for i := 0; i < len(encoded); i += 2 {
		parts = append(parts, encoded[i:i+2])
	}
	return strings.Join(parts, ":")
}

func generateTransportPrivateKey(algorithm string) (*TransportPrivateKey, error) {
	switch algorithm {
	case AlgorithmEd25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(priv))
		if err != nil {
			return nil, err
		}
		return &TransportPrivateKey{
			Kind:       TransportKeyRawPublicKey,
			Algorithm:  AlgorithmEd25519,
			PublicKey:  append([]byte(nil), pub...),
			PrivateKey: privDER,
		}, nil
	case AlgorithmECDSAP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, err
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return &TransportPrivateKey{
			Kind:       TransportKeyRawPublicKey,
			Algorithm:  AlgorithmECDSAP256,
			PublicKey:  pubDER,
			PrivateKey: privDER,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported transport key algorithm %q", algorithm)
	}
}

// PEMEncodePrivateKey encodes a DER private key as PEM.
// It uses "EC PRIVATE KEY" for SEC1 ECDSA keys and "PRIVATE KEY" for PKCS#8.
func PEMEncodePrivateKey(der []byte) ([]byte, error) {
	if len(der) == 0 {
		return nil, fmt.Errorf("empty private key DER")
	}
	blockType := "PRIVATE KEY"
	if _, err := x509.ParseECPrivateKey(der); err == nil {
		blockType = "EC PRIVATE KEY"
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), nil
}

// PEMEncodePublicKey encodes a DER public key as PKIX PEM.
func PEMEncodePublicKey(publicKey []byte) ([]byte, error) {
	if len(publicKey) == 0 {
		return nil, fmt.Errorf("empty public key DER")
	}
	der := publicKey
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("parse public key DER: %w", err)
		}
		var marshalErr error
		der, marshalErr = x509.MarshalPKIXPublicKey(ed25519.PublicKey(publicKey))
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal ed25519 public key: %w", marshalErr)
		}
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// KeyTypeForAlgorithm returns the StrongSwan VICI load-key type for an algorithm.
func KeyTypeForAlgorithm(algorithm string) string {
	switch algorithm {
	case AlgorithmEd25519:
		return "ed25519"
	case AlgorithmECDSAP256:
		return "ecdsa"
	default:
		return "any"
	}
}

// KeyTypeAny returns the StrongSwan VICI load-key type that lets charon auto-detect the key format.
func KeyTypeAny() string { return "any" }

// DeriveTransportPublicKey extracts the public key from a PKCS#8 or SEC1
// private key for the supported transport algorithms.
func DeriveTransportPublicKey(privateKey []byte, algorithm string) ([]byte, error) {
	if len(privateKey) == 0 {
		return nil, fmt.Errorf("empty private key")
	}
	switch algorithm {
	case AlgorithmEd25519:
		key, err := x509.ParsePKCS8PrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("parse ed25519 private key: %w", err)
		}
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unexpected ed25519 private key type %T", key)
		}
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("unexpected ed25519 public key type %T", priv.Public())
		}
		return []byte(pub), nil
	case AlgorithmECDSAP256:
		key, err := x509.ParsePKCS8PrivateKey(privateKey)
		if err != nil {
			// Fallback to SEC1 parsing.
			ecKey, err2 := x509.ParseECPrivateKey(privateKey)
			if err2 != nil {
				return nil, fmt.Errorf("parse ecdsa private key: %w", err)
			}
			key = ecKey
		}
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unexpected ecdsa private key type %T", key)
		}
		return x509.MarshalPKIXPublicKey(&priv.PublicKey)
	default:
		return nil, fmt.Errorf("unsupported transport key algorithm %q", algorithm)
	}
}
