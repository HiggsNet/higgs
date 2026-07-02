package ipsec

import (
	"context"
	"encoding/json"
	"iter"
	"reflect"
	"strings"
	"testing"
	"time"

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
	subscribed   []string
	eventCh      chan<- vici.Event
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

func (s *fakeGoviciSession) Subscribe(events ...string) error {
	s.subscribed = append(s.subscribed, events...)
	return nil
}

func (s *fakeGoviciSession) NotifyEvents(ch chan<- vici.Event) {
	s.eventCh = ch
}

func (s *fakeGoviciSession) StopEvents(ch chan<- vici.Event) {
	if s.eventCh == ch {
		s.eventCh = nil
	}
}

type blockingGoviciSession struct{}

func (s blockingGoviciSession) Call(ctx context.Context, _ string, _ *vici.Message) (*vici.Message, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s blockingGoviciSession) CallStreaming(ctx context.Context, _ string, _ string, _ *vici.Message) iter.Seq2[*vici.Message, error] {
	return func(yield func(*vici.Message, error) bool) {
		<-ctx.Done()
		yield(nil, ctx.Err())
	}
}

func (s blockingGoviciSession) Close() error {
	return nil
}

type blockingVICIClient struct {
	calls   chan string
	release chan struct{}
}

func (c *blockingVICIClient) Call(ctx context.Context, cmd string, _ map[string]any) (map[string]any, error) {
	select {
	case c.calls <- cmd:
	default:
	}
	select {
	case <-c.release:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *blockingVICIClient) CallStreaming(context.Context, string, string, map[string]any) ([]map[string]any, error) {
	return nil, nil
}

func TestGoviciClientMarshalsLoadConnectionMessage(t *testing.T) {
	session := &fakeGoviciSession{}
	client := &GoviciClient{Session: session}
	spec := sampleStrongSwanSpec()

	if err := (&StrongSwanDriver{VICI: client}).LoadConnection(context.Background(), spec); err != nil {
		t.Fatalf("LoadConnection: %v", err)
	}
	if session.callCmd != "load-conn" {
		t.Fatalf("cmd = %q, want load-conn", session.callCmd)
	}
	conn, ok := session.callIn[spec.TransportID].(map[string]any)
	if !ok {
		t.Fatalf("connection missing from call input: %#v", session.callIn)
	}
	if conn["version"] != "2" || conn["remote_port"] != "4500" || conn["encap"] != "yes" || conn["mobike"] != "no" || conn["unique"] != "never" {
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
	if child["start_action"] != "trap" {
		t.Fatalf("child start_action = %#v, want trap", child["start_action"])
	}
}

func TestStrongSwanDriverBoundsVICIOperation(t *testing.T) {
	client := &GoviciClient{Session: blockingGoviciSession{}}
	driver := &StrongSwanDriver{
		VICI:             client,
		OperationTimeout: 10 * time.Millisecond,
	}

	start := time.Now()
	err := driver.LoadConnection(context.Background(), sampleStrongSwanSpec())
	if err == nil {
		t.Fatal("LoadConnection error = nil, want timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("LoadConnection took too long: %s", time.Since(start))
	}
	if !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
		t.Fatalf("LoadConnection error = %v, want deadline exceeded", err)
	}
}

func TestStrongSwanDriverInitiateChildAsyncReturnsAndCoalesces(t *testing.T) {
	client := &blockingVICIClient{
		calls:   make(chan string, 2),
		release: make(chan struct{}),
	}
	driver := &StrongSwanDriver{
		VICI:          client,
		InitiateAsync: true,
	}

	start := time.Now()
	if err := driver.InitiateChild(context.Background(), "ipsec-main-child"); err != nil {
		t.Fatalf("InitiateChild: %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("InitiateChild blocked for %s", time.Since(start))
	}
	if err := driver.InitiateChild(context.Background(), "ipsec-main-child"); err != nil {
		t.Fatalf("second InitiateChild: %v", err)
	}
	select {
	case cmd := <-client.calls:
		if cmd != "initiate" {
			t.Fatalf("command = %q, want initiate", cmd)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for async initiate call")
	}
	select {
	case cmd := <-client.calls:
		t.Fatalf("unexpected duplicate async call %q", cmd)
	case <-time.After(20 * time.Millisecond):
	}
	close(client.release)
}

func TestStrongSwanDriverLogsVICILoadConnectionConfig(t *testing.T) {
	session := &fakeGoviciSession{}
	client := &GoviciClient{Session: session}
	spec := sampleStrongSwanSpec()
	var gotEvent string
	var gotFields map[string]any
	driver := &StrongSwanDriver{
		VICI: client,
		LogConfig: func(event string, fields map[string]any) {
			gotEvent = event
			gotFields = fields
		},
	}

	if err := driver.LoadConnection(context.Background(), spec); err != nil {
		t.Fatalf("LoadConnection: %v", err)
	}
	if gotEvent != "vici_load_conn" {
		t.Fatalf("event = %q, want vici_load_conn", gotEvent)
	}
	if gotFields["connection"] != spec.TransportID || gotFields["command"] != "load-conn" {
		t.Fatalf("fields = %+v", gotFields)
	}
	configJSON, ok := gotFields["config_json"].(string)
	if !ok || configJSON == "" {
		t.Fatalf("config_json = %#v", gotFields["config_json"])
	}
	for _, want := range []string{spec.TransportID, `"remote_port":"4500"`, `"encap":"yes"`, `"mobike":"no"`, `"unique":"never"`, ChildSAName(spec)} {
		if !strings.Contains(configJSON, want) {
			t.Fatalf("config_json missing %q: %s", want, configJSON)
		}
	}
}

func TestSanitizeVICIConfigForLogRedactsKeyMaterial(t *testing.T) {
	sanitized := sanitizeVICIConfigForLog(map[string]any{
		"conn": map[string]any{
			"local": map[string]any{
				"pubkeys": []string{"-----BEGIN PUBLIC KEY-----\nsecret-ish\n-----END PUBLIC KEY-----"},
			},
			"remote": map[string]any{
				"data": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
			},
		},
	}).(map[string]any)
	data, err := json.Marshal(sanitized)
	if err != nil {
		t.Fatalf("Marshal sanitized config: %v", err)
	}
	text := string(data)
	if strings.Contains(text, "BEGIN") || strings.Contains(text, "secret") {
		t.Fatalf("sanitized config leaked key material: %#v", sanitized)
	}
	conn := sanitized["conn"].(map[string]any)
	local := conn["local"].(map[string]any)
	remote := conn["remote"].(map[string]any)
	if local["pubkeys"] != "present:1" || remote["data"] != "present" {
		t.Fatalf("sanitized config = %#v", sanitized)
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
			"state":       "ESTABLISHED",
			"child-sas": map[string]any{
				"ipsec-main-ab-child": map[string]any{
					"reqid":     "17",
					"if-id-out": "4d",
					"state":     "INSTALLED",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	session := &fakeGoviciSession{streamEvents: []*vici.Message{event}}
	client := &GoviciClient{Session: session}

	states, err := (&StrongSwanDriver{VICI: client}).ListSAs(context.Background())
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
		IKEState:       "ESTABLISHED",
		ChildState:     "INSTALLED",
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

func TestGoviciClientStreamsListConnections(t *testing.T) {
	event, err := vici.MarshalMessage(map[string]any{
		"ipsec-main-ab": map[string]any{
			"remote_addrs": []string{"198.51.100.20"},
			"remote_port":  "4500",
			"local": map[string]any{
				"id": "node-a.catofes.",
			},
			"remote": map[string]any{
				"id": "node-b.catofes.",
			},
		},
	})
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	session := &fakeGoviciSession{streamEvents: []*vici.Message{event}}
	client := &GoviciClient{Session: session}

	states, err := (&StrongSwanDriver{VICI: client}).ListConnections(context.Background())
	if err != nil {
		t.Fatalf("ListConnections: %v", err)
	}
	if session.streamCmd != "list-conns" || session.streamEvent != "list-conn" {
		t.Fatalf("stream command = %q/%q", session.streamCmd, session.streamEvent)
	}
	want := []ConnectionState{{
		Name:           "ipsec-main-ab",
		LocalIdentity:  "node-a.catofes.",
		RemoteIdentity: "node-b.catofes.",
		RemoteEndpoint: "198.51.100.20:4500",
	}}
	if !reflect.DeepEqual(states, want) {
		t.Fatalf("states:\n got %#v\nwant %#v", states, want)
	}
}

func TestGoviciClientSubscribesAndParsesLifecycleEvents(t *testing.T) {
	session := &fakeGoviciSession{}
	client := &GoviciClient{Session: session}
	events, stop, err := client.SubscribeEvents(context.Background(), "child-updown", "ike-updown")
	if err != nil {
		t.Fatalf("SubscribeEvents: %v", err)
	}
	defer stop()
	if !reflect.DeepEqual(session.subscribed, []string{"child-updown", "ike-updown"}) {
		t.Fatalf("subscribed = %+v", session.subscribed)
	}
	msg, err := vici.MarshalMessage(map[string]any{
		"ike":         "ipsec-main-ab",
		"child":       "ipsec-main-ab-child{2}",
		"up":          "yes",
		"if_id_out":   "77",
		"reqid":       "17",
		"local-id":    "node-a.catofes.",
		"remote-id":   "node-b.catofes.",
		"local-host":  "198.51.100.10",
		"local-port":  "4500",
		"remote-host": "198.51.100.20",
		"remote-port": "4500",
	})
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	session.eventCh <- vici.Event{Name: "child-updown", Message: msg}
	select {
	case ev := <-events:
		if ev.Name != "child-updown" || ev.Connection != "ipsec-main-ab" || ev.ChildSA != "ipsec-main-ab-child" || !ev.Up {
			t.Fatalf("event = %+v", ev)
		}
		if ev.XFRMIfID != 77 || ev.ReqID != 17 || ev.RemoteEndpoint != "198.51.100.20:4500" {
			t.Fatalf("event numeric/endpoint fields = %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for lifecycle event")
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
