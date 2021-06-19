package higgs

import "encoding/json"

type transportMessage struct {
}

type nodeMessage struct {
	Domain    string
	PublicKey string
	Timestamp string
	Sign      string
	Transport []transportMessage
	transport []transport
}

func (s *nodeMessage) getDomain() string {
	return s.Domain
}

func (s *nodeMessage) getMessage() string {
	if d, err := json.Marshal(
		&nodeMessage{
			Domain:    s.Domain,
			PublicKey: s.PublicKey,
			Timestamp: s.Timestamp,
			Transport: s.Transport,
		}); err != nil {
		return string(d)
	}
	return ""
}
func (s *nodeMessage) getSign() string {
	return s.Sign
}
func (s *nodeMessage) setSign(sign string) {
	s.Sign = sign
}
