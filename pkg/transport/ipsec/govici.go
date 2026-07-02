package ipsec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"strings"
	"sync"

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

type VICIClientFactory func() (VICIClient, func() error, error)

type ReconnectingVICIClient struct {
	mu      sync.Mutex
	factory VICIClientFactory
	client  VICIClient
	closeFn func() error
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

func NewReconnectingGoviciClient(socketPath string) (*ReconnectingVICIClient, error) {
	factory := func() (VICIClient, func() error, error) {
		client, err := NewGoviciClient(socketPath)
		if err != nil {
			return nil, nil, err
		}
		return client, client.Close, nil
	}
	client, closeFn, err := factory()
	if err != nil {
		return nil, err
	}
	return &ReconnectingVICIClient{factory: factory, client: client, closeFn: closeFn}, nil
}

func NewReconnectingVICIClient(factory VICIClientFactory) (*ReconnectingVICIClient, error) {
	if factory == nil {
		return nil, fmt.Errorf("vici client factory is required")
	}
	client, closeFn, err := factory()
	if err != nil {
		return nil, err
	}
	return &ReconnectingVICIClient{factory: factory, client: client, closeFn: closeFn}, nil
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

func (c *ReconnectingVICIClient) Call(ctx context.Context, cmd string, in map[string]any) (map[string]any, error) {
	client, err := c.current()
	if err != nil {
		return nil, err
	}
	out, err := client.Call(ctx, cmd, in)
	if !isVICIReconnectError(err) {
		return out, err
	}
	client, reconnectErr := c.reconnect(client)
	if reconnectErr != nil {
		return nil, fmt.Errorf("%w; reconnect vici: %v", err, reconnectErr)
	}
	return client.Call(ctx, cmd, in)
}

func (c *ReconnectingVICIClient) CallStreaming(ctx context.Context, cmd string, event string, in map[string]any) ([]map[string]any, error) {
	client, err := c.current()
	if err != nil {
		return nil, err
	}
	out, err := client.CallStreaming(ctx, cmd, event, in)
	if !isVICIReconnectError(err) {
		return out, err
	}
	client, reconnectErr := c.reconnect(client)
	if reconnectErr != nil {
		return nil, fmt.Errorf("%w; reconnect vici: %v", err, reconnectErr)
	}
	return client.CallStreaming(ctx, cmd, event, in)
}

func (c *ReconnectingVICIClient) SubscribeEvents(ctx context.Context, events ...string) (<-chan VICIEvent, func(), error) {
	client, err := c.current()
	if err != nil {
		return nil, nil, err
	}
	subscriber, ok := client.(VICIEventClient)
	if !ok {
		return nil, nil, fmt.Errorf("vici client does not support event subscription")
	}
	out, stop, err := subscriber.SubscribeEvents(ctx, events...)
	if !isVICIReconnectError(err) {
		return out, stop, err
	}
	client, reconnectErr := c.reconnect(client)
	if reconnectErr != nil {
		return nil, nil, fmt.Errorf("%w; reconnect vici: %v", err, reconnectErr)
	}
	subscriber, ok = client.(VICIEventClient)
	if !ok {
		return nil, nil, fmt.Errorf("vici client does not support event subscription")
	}
	return subscriber.SubscribeEvents(ctx, events...)
}

func (c *ReconnectingVICIClient) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	closeFn := c.closeFn
	c.client = nil
	c.closeFn = nil
	c.mu.Unlock()
	if closeFn != nil {
		return closeFn()
	}
	return nil
}

func (c *ReconnectingVICIClient) current() (VICIClient, error) {
	if c == nil {
		return nil, errMissingGoviciSession()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == nil {
		return nil, errMissingGoviciSession()
	}
	return c.client, nil
}

func (c *ReconnectingVICIClient) reconnect(stale VICIClient) (VICIClient, error) {
	if c == nil {
		return nil, errMissingGoviciSession()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != stale && c.client != nil {
		return c.client, nil
	}
	if c.closeFn != nil {
		_ = c.closeFn()
	}
	client, closeFn, err := c.factory()
	if err != nil {
		c.client = nil
		c.closeFn = nil
		return nil, err
	}
	c.client = client
	c.closeFn = closeFn
	return client, nil
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

func isVICIReconnectError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	text := strings.ToLower(err.Error())
	for _, token := range []string{
		"broken pipe",
		"connection reset",
		"connection refused",
		"use of closed network connection",
		"transport endpoint is not connected",
		"unexpected eof",
	} {
		if strings.Contains(text, token) {
			return true
		}
	}
	return false
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
