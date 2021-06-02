package higgs

func (h *Higgs) init() error {
	return nil
}

//PushMetadata func push server info to etcd center.
func (h *Higgs) PushMetadata() error {
	err := h.init()
	if err != nil {
		return err
	}
	return h.pushMetadata()
}
