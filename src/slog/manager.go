package slog

import (
	"crypto/ed25519"
	"time"
)

type Manager struct {
	entries map[string]Entry
}

func (m *Manager) Init(RootKey string) {
	m.entries = make(map[string]Entry)
	rootKey := KeyEntry{
		DefaultEntry: DefaultEntry{
			Name:     ".",
			CreateAt: time.Now(),
			Action:   EntryActionAccept,
			SignBy:   ".",
		},
		Value: RootKey,
	}
	_, rootKey.privateKey, _ = ed25519.GenerateKey(nil)
	rootKey.Sign(&rootKey, time.Hour*10*24*365)
	m.entries["."] = &rootKey
}

func (m *Manager) AddEntry(e Entry) {
	if m.Valid(e) {
		m.entries[e.GetName()] = e
	}
}

func (m *Manager) Valid(e Entry) bool {
	if parent := e.GetParent(m); parent != nil {
		if e.Valide(parent) && parent.Action == EntryActionAccept {
			return true
		}
	}
	return false
}

func (m *Manager) GetEntry(name string) Entry {
	if entry, ok := m.entries[name]; ok {
		return entry
	}
	return nil
}
