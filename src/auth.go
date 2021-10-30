package higgs

import (
	"crypto/ed25519"
	"encoding/json"
)

type AuthMessage struct {
	Domain    string `hcl:"Domain,attr"`
	Key       string `hcl:"Key,attr"`
	Sign      string `hcl:"Sign,attr"`
	Timestamp int64  `hcl:"Timestamp,attr"`
	key       ed25519.PublicKey
	managed   bool
}

func (s *AuthMessage) GetDomain() string {
	return s.Domain
}

func (s *AuthMessage) GetMessage() string {
	if d, err := json.Marshal(
		&AuthMessage{
			Domain:    s.Domain,
			Key:       s.Key,
			Timestamp: s.Timestamp,
		}); err == nil {
		return string(d)
	}
	return ""
}

func (s *AuthMessage) GetSign() string {
	return s.Sign
}

func (s *AuthMessage) SetSign(sign string) {
	s.Sign = sign
}

func (s *AuthMessage) GetKey() ed25519.PublicKey {
	if s.key == nil {
		s.key = ParsePublicKey(s.Key)
	}
	return s.key
}

func (s *AuthMessage) Dump() string {
	data, _ := json.Marshal(s)
	return string(data)
}

func (s *AuthMessage) Load(input string) error {
	return json.Unmarshal([]byte(input), s)
}

func (s *AuthMessage) GetTimestamp() int64 {
	return s.Timestamp
}
