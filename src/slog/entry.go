package slog

import (
	"crypto/ed25519"
	"crypto/md5"
	"errors"
	"time"
)

type EntryAction int

var (
	ErrPrivateKeyNotFound = errors.New("private key not found")
)

const (
	EntryActionAccept EntryAction = iota
	EntryActionReject
)

type Entry interface {
	GetName() string
	Sign(parent *KeyEntry, expire time.Duration) error
	Valide(parent *KeyEntry) bool
	GetParent(manager *Manager) *KeyEntry
}

type DefaultEntry struct {
	Name      string
	Action    EntryAction
	CreateAt  time.Time
	ExpireAt  time.Time
	SignBy    string
	Signature string
}

func (e *DefaultEntry) GetName() string {
	return e.Name
}

/*
"." 根
".example" example子节点, value是公钥
".example.example2" example的子节点：example2, value是公钥
*/

type KeyEntry struct {
	DefaultEntry
	Value      string
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func (e *KeyEntry) Init() {
	e.publicKey = ed25519.PublicKey(e.Value)
}

func (e *KeyEntry) GetParent(manager *Manager) *KeyEntry {
	if parent, ok := manager.GetEntry(e.SignBy).(*KeyEntry); ok {
		return parent
	}
	return nil
}

func (e *KeyEntry) toBytes() []byte {
	result := make([]byte, 0)
	appendHash := func(data []byte) {
		hash := md5.Sum(data)
		result = append(result, hash[:]...)
	}
	appendHash([]byte(e.Name))
	appendHash([]byte(e.Value))
	appendHash([]byte(e.SignBy))
	appendHash([]byte(e.CreateAt.String()))
	appendHash([]byte(e.ExpireAt.String()))
	result = append(result, byte(e.Action))
	hash := md5.Sum(result)
	return hash[:]
}

func (e *KeyEntry) Sign(parent *KeyEntry, expire time.Duration) error {
	e.SignBy = parent.Name
	e.CreateAt = time.Now()
	e.ExpireAt = e.CreateAt.Add(expire)
	if parent.privateKey == nil {
		return ErrPrivateKeyNotFound
	}
	e.Signature = string(ed25519.Sign(parent.privateKey, e.toBytes()))
	return nil
}

func (e *KeyEntry) Valide(parent *KeyEntry) bool {
	return ed25519.Verify(parent.publicKey, e.toBytes(), []byte(e.Signature))
}
