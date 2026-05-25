package node

import (
	"crypto/ed25519"
	"crypto/md5"
	"strings"
)

type entryAction int

const (
	entryActionAccept entryAction = iota
	entryActionReject
)

/*
"." 根
".catofes" 代表catofes, value是公钥
".catofes.node1" 代表catofes的节点：node1, value是公钥
".catofes.node1._address" 代表catofes的节点：node1的可用地址
*/
type entry struct {
	Name      string
	Value     string
	Action    entryAction
	Signature string
}

func (e *entry) toBytes() []byte {
	result := make([]byte, 0)
	appendHash := func(data []byte) {
		hash := md5.Sum(data)
		result = append(result, hash[:]...)
	}

	appendHash([]byte(e.Name))
	appendHash([]byte(e.Value))
	result = append(result, byte(e.Action))

	return result
}

func (e *entry) sign(privateKey ed25519.PrivateKey) {
	e.Signature = string(ed25519.Sign(privateKey, e.toBytes()))
}

func (e *entry) valide(key ed25519.PublicKey) bool {
	return ed25519.Verify(key, e.toBytes(), []byte(e.Signature))
}

func (e *entry) split() []string {
	result := make([]string, 0)
	for i := 0; i < len(e.Name); i++ {
		if e.Name[i] == '.' {
			result = append(result, e.Name[:i])
		}
	}
	return result
}

func (e *entry) isAddress() bool {
	tmp := strings.Split(e.Name, ".")
	if len(tmp) > 0 && tmp[len(tmp)-1] == "_address" {
		return true
	}
	return false
}

type valider struct {
	Path          string
	RootPublicKey string
	Entries       map[string]entry
}

func (v *valider) createRoot() {
	entry := entry{
		Name:   ".",
		Value:  v.RootPublicKey,
		Action: entryActionAccept,
	}
	v.Entries["."] = entry
}

func (v *valider) addEntry(e entry) {

}

func (v *valider) valideKey(e entry) bool {
	accept := false
	parentsName := e.split()
	for _, name := range parentsName {
		if entry, ok := v.Entries[name]; ok {
			if entry.Action == entryActionAccept {
				accept = true
			} else {
				return false
			}
		}
	}
	return accept
}

func (v *valider) valideAddress(e entry) bool {
	accept := false
	parentsName := e.split()
	for _, name := range parentsName {
		if entry, ok := v.Entries[name]; ok {
			if entry.Action == entryActionAccept {
				accept = true
			} else {
				return false
			}
		}
	}
	return accept
}

func (v *valider) valide(e entry) bool {
	if e.isAddress() {
		return v.valideAddress(e)
	}
	return v.valideKey(e)
}
