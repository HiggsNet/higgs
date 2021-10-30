package higgs

import "encoding/json"

type transportMessage struct {
}

type NodeMessage struct {
	Domain    string
	Addresses string
	Timestamp int64
	Sign      string
	List      map[string]int64
}

func (s *NodeMessage) GetDomain() string {
	return s.Domain
}

func (s *NodeMessage) GetMessage() string {
	if d, err := json.Marshal(
		&NodeMessage{
			Domain:    s.Domain,
			Addresses: s.Addresses,
			Timestamp: s.Timestamp,
			List:      s.List,
		}); err == nil {
		return string(d)
	}
	return ""
}
func (s *NodeMessage) GetSign() string {
	return s.Sign
}
func (s *NodeMessage) SetSign(sign string) {
	s.Sign = sign
}

func (s *NodeMessage) Dump() string {
	data, _ := json.Marshal(s)
	return string(data)
}

func (s *NodeMessage) Load(input string) error {
	return json.Unmarshal([]byte(input), s)
}

func (s *NodeMessage) GetTimestamp() int64 {
	return s.Timestamp
}
