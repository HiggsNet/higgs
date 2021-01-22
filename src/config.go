package higgs

//Higgs is the model of higgs.conf
type Higgs struct{
	Name string `hcl:"name,attr"`
	Etcd string `hcl:"etcd,attr"`
	CA string `hcl:"ca,attr`
	PrivateKey string `hcl:"pirvate_key",attr`
}

func (h *Higgs) Load(){

}