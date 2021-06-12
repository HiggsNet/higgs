package higgs

type AnnounceMessage struct {
	Domain  string
	Message string
	Sign    string
}

func (s *AnnounceMessage) valid() {
	//todo
}
