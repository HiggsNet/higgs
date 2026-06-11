package ipsec

import (
	"context"
	"iter"
	"reflect"
	"testing"

	"github.com/strongswan/govici/vici"
)

type fakeGoviciSession struct {
	callCmd      string
	callIn       map[string]any
	streamCmd    string
	streamEvent  string
	streamIn     map[string]any
	callOut      *vici.Message
	streamEvents []*vici.Message
}

func (s *fakeGoviciSession) Call(_ context.Context, cmd string, in *vici.Message) (*vici.Message, error) {
	s.callCmd = cmd
	s.callIn = goviciMessageToMap(in)
	return s.callOut, nil
}

func (s *fakeGoviciSession) CallStreaming(_ context.Context, cmd string, event string, in *vici.Message) iter.Seq2[*vici.Message, error] {
	s.streamCmd = cmd
	s.streamEvent = event
	s.streamIn = goviciMessageToMap(in)
	return func(yield func(*vici.Message, error) bool) {
		for _, msg := range s.streamEvents {
			if !yield(msg, nil) {
				return
			}
		}
	}
}

func (s *fakeGoviciSession) Close() error {
	return nil
}

func TestGoviciClientMarshalsLoadConnectionMessage(t *testing.T) {
	session := &fakeGoviciSession{}
	client := &GoviciClient{Session: session}
	spec := sampleStrongSwanSpec()

	if err := (StrongSwanDriver{VICI: client}).LoadConnection(context.Background(), spec); err != nil {
		t.Fatalf("LoadConnection: %v", err)
	}
	if session.callCmd != "load-conn" {
		t.Fatalf("cmd = %q, want load-conn", session.callCmd)
	}
	conn, ok := session.callIn[spec.TransportID].(map[string]any)
	if !ok {
		t.Fatalf("connection missing from call input: %#v", session.callIn)
	}
	if conn["version"] != "2" || conn["remote_port"] != "4500" {
		t.Fatalf("connection scalar fields = %#v", conn)
	}
	children, ok := conn["children"].(map[string]any)
	if !ok {
		t.Fatalf("children = %#v", conn["children"])
	}
	child, ok := children[ChildSAName(spec)].(map[string]any)
	if !ok {
		t.Fatalf("child missing from children: %#v", children)
	}
	if child["if_id_in"] != "77" || child["if_id_out"] != "77" {
		t.Fatalf("child if_id fields = %#v", child)
	}
}

func TestGoviciClientStreamsListSAs(t *testing.T) {
	event, err := vici.MarshalMessage(map[string]any{
		"ipsec-main-ab": map[string]any{
			"local-host":  "198.51.100.10",
			"local-port":  "4500",
			"local-id":    "node-a.catofes.",
			"remote-host": "198.51.100.20",
			"remote-port": "4500",
			"remote-id":   "node-b.catofes.",
			"child-sas": map[string]any{
				"ipsec-main-ab-child": map[string]any{
					"reqid":     "17",
					"if-id-out": "77",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	session := &fakeGoviciSession{streamEvents: []*vici.Message{event}}
	client := &GoviciClient{Session: session}

	states, err := (StrongSwanDriver{VICI: client}).ListSAs(context.Background())
	if err != nil {
		t.Fatalf("ListSAs: %v", err)
	}
	if session.streamCmd != "list-sas" || session.streamEvent != "list-sa" {
		t.Fatalf("stream command = %q/%q", session.streamCmd, session.streamEvent)
	}
	want := []SAState{{
		Name:           "ipsec-main-ab",
		Peer:           "198.51.100.20",
		ChildSA:        "ipsec-main-ab-child",
		XFRMIfID:       77,
		ReqID:          17,
		LocalIdentity:  "node-a.catofes.",
		RemoteIdentity: "node-b.catofes.",
		LocalEndpoint:  "198.51.100.10:4500",
		RemoteEndpoint: "198.51.100.20:4500",
		Endpoint:       "198.51.100.20:4500",
		Established:    true,
	}}
	if !reflect.DeepEqual(states, want) {
		t.Fatalf("states:\n got %#v\nwant %#v", states, want)
	}
}

func sampleStrongSwanSpec() TransportLinkSpec {
	return TransportLinkSpec{
		TransportID:   "ipsec-main-ab",
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		InterfaceName: "hgsab0",
		XFRMIfID:      77,
		ContactPoints: []ContactPoint{{
			Address:  "198.51.100.20",
			IKEPort:  4500,
			NATTPort: 4500,
		}},
	}
}
