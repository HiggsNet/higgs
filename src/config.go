package higgs

import "github.com/hashicorp/hcl/v2"

type config struct {
	Domain    string      `hcl:"domain,attr"`
	Zone      string      `hcl:"zone,attr"`
	Root      string      `hcl:"root,attr"`
	Transport []Transport `hcl:"transport,block"`
	// Isolation Isolation   `hcl:"isolation,block"` // optional, params for the separation of underlay and overlay
	// Babeld    Babeld      `hcl:"babeld,block"`    // optional, integration with babeld
	Remarks hcl.Body `hcl:"remarks,remain"` // optional, additional information
}

type Transport struct {
	Type      string `hcl:"type,label"`
	MTU       int    `hcl:"mtu,attr"`
	IFPrefix  string `hcl:"ifprefix"`
	Addresses string `hcl:"address"`

	//Isolation Overwrite
	Transit string `hcl:"transit"` // optional, the namespace to create sockets in
	Target  string `hcl:"target"`  // optional, the namespace to move interfaces into

	//Wireguard Config
	PrivateKey string `hcl:"private_key"`
	Port       int    `hcl:"port"`

	//WireguardGo Config
	WgGoInterface string `hcl:"go_interface"`

	//VXLAN Config
	Mac string `hcl:"mac"`
	VNI int    `hcl:"vni"`
}

type Isolation struct {
	IFGroup int    `hcl:"ifgroup,attr"`     // mandatory, interface group, for recognizing managed interfaces
	Transit string `hcl:"transit,optional"` // optional, the namespace to create sockets in
	Target  string `hcl:"target,optional"`  // optional, the namespace to move interfaces into
}
