package higgs

import "encoding/json"

type PeerMessage struct {
	Domain    string
	Addresses string
	Timestamp int64
	Sign      string
}

func (s *PeerMessage) GetDomain() string {
	return s.Domain
}

func (s *PeerMessage) GetMessage() string {
	if d, err := json.Marshal(
		&NodeMessage{
			Domain:    s.Domain,
			Addresses: s.Addresses,
			Timestamp: s.Timestamp,
		}); err == nil {
		return string(d)
	}
	return ""
}
func (s *PeerMessage) GetSign() string {
	return s.Sign
}
func (s *PeerMessage) SetSign(sign string) {
	s.Sign = sign
}

func (s *PeerMessage) Dump() string {
	data, _ := json.Marshal(s)
	return string(data)
}

func (s *PeerMessage) Load(input string) error {
	return json.Unmarshal([]byte(input), s)
}

func (s *PeerMessage) GetTimestamp() int64 {
	return s.Timestamp
}
