package ipsec

import (
	"context"
	"fmt"
	"iter"

	"github.com/strongswan/govici/vici"
)

type GoviciSession interface {
	Call(context.Context, string, *vici.Message) (*vici.Message, error)
	CallStreaming(context.Context, string, string, *vici.Message) iter.Seq2[*vici.Message, error]
	Close() error
}

type GoviciEventSession interface {
	Subscribe(events ...string) error
	NotifyEvents(chan<- vici.Event)
	StopEvents(chan<- vici.Event)
}

type GoviciClient struct {
	Session GoviciSession
}

func NewGoviciClient(socketPath string) (*GoviciClient, error) {
	var opts []vici.SessionOption
	if socketPath != "" {
		opts = append(opts, vici.WithSocketPath(socketPath))
	}
	session, err := vici.NewSession(opts...)
	if err != nil {
		return nil, err
	}
	return &GoviciClient{Session: session}, nil
}

func (c *GoviciClient) Call(ctx context.Context, cmd string, in map[string]any) (map[string]any, error) {
	if c == nil || c.Session == nil {
		return nil, errMissingGoviciSession()
	}
	msg, err := goviciMarshal(in)
	if err != nil {
		return nil, err
	}
	out, err := c.Session.Call(ctx, cmd, msg)
	if err != nil {
		return nil, err
	}
	return goviciMessageToMap(out), nil
}

func (c *GoviciClient) CallStreaming(ctx context.Context, cmd string, event string, in map[string]any) ([]map[string]any, error) {
	if c == nil || c.Session == nil {
		return nil, errMissingGoviciSession()
	}
	msg, err := goviciMarshal(in)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for msg, err := range c.Session.CallStreaming(ctx, cmd, event, msg) {
		if err != nil {
			return nil, err
		}
		out = append(out, goviciMessageToMap(msg))
	}
	return out, nil
}

func (c *GoviciClient) Close() error {
	if c == nil || c.Session == nil {
		return nil
	}
	return c.Session.Close()
}

func (c *GoviciClient) SubscribeEvents(_ context.Context, events ...string) (<-chan VICIEvent, func(), error) {
	if c == nil || c.Session == nil {
		return nil, nil, errMissingGoviciSession()
	}
	session, ok := c.Session.(GoviciEventSession)
	if !ok {
		return nil, nil, fmt.Errorf("govici session does not support event subscription")
	}
	if err := session.Subscribe(events...); err != nil {
		return nil, nil, err
	}
	raw := make(chan vici.Event, 16)
	out := make(chan VICIEvent, 16)
	session.NotifyEvents(raw)
	stop := func() {
		session.StopEvents(raw)
	}
	go func() {
		defer close(out)
		for ev := range raw {
			out <- parseVICIEvent(ev.Name, goviciMessageToMap(ev.Message))
		}
	}()
	return out, stop, nil
}

func errMissingGoviciSession() error {
	return fmt.Errorf("govici session is required")
}

func goviciMarshal(in map[string]any) (*vici.Message, error) {
	if in == nil {
		return nil, nil
	}
	return vici.MarshalMessage(in)
}

func goviciMessageToMap(msg *vici.Message) map[string]any {
	if msg == nil {
		return nil
	}
	out := make(map[string]any, len(msg.Keys()))
	for _, key := range msg.Keys() {
		out[key] = goviciValueToAny(msg.Get(key))
	}
	return out
}

func goviciValueToAny(value any) any {
	switch v := value.(type) {
	case *vici.Message:
		return goviciMessageToMap(v)
	case []string:
		return append([]string(nil), v...)
	default:
		return v
	}
}
