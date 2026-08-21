package ipsec

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type privateKeyVICIClient struct {
	mu        sync.Mutex
	commands  []string
	inputs    []map[string]any
	unloadErr error
}

func (c *privateKeyVICIClient) Call(_ context.Context, command string, input map[string]any) (map[string]any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commands = append(c.commands, command)
	c.inputs = append(c.inputs, input)
	if command == "unload-key" && c.unloadErr != nil {
		return nil, c.unloadErr
	}
	if command == "load-key" {
		return map[string]any{"id": "shared-key-id"}, nil
	}
	return map[string]any{"success": "yes"}, nil
}

func (c *privateKeyVICIClient) CallStreaming(context.Context, string, string, map[string]any) ([]map[string]any, error) {
	return nil, nil
}

func (c *privateKeyVICIClient) commandCount(command string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for _, got := range c.commands {
		if got == command {
			count++
		}
	}
	return count
}

func TestStrongSwanDriverSharesPrivateKeyByFingerprint(t *testing.T) {
	key, _, err := GenerateTransportKeyRecord(AlgorithmEd25519, time.Unix(1000, 0), 0)
	if err != nil {
		t.Fatalf("GenerateTransportKeyRecord: %v", err)
	}
	client := &privateKeyVICIClient{}
	driver := &StrongSwanDriver{VICI: client}

	if err := driver.LoadPrivateKey(context.Background(), "link-a", key.PrivateKey, key.Algorithm); err != nil {
		t.Fatalf("LoadPrivateKey(link-a): %v", err)
	}
	if err := driver.LoadPrivateKey(context.Background(), "link-a", key.PrivateKey, key.Algorithm); err != nil {
		t.Fatalf("LoadPrivateKey(link-a repeat): %v", err)
	}
	if err := driver.LoadPrivateKey(context.Background(), "link-b", key.PrivateKey, key.Algorithm); err != nil {
		t.Fatalf("LoadPrivateKey(link-b): %v", err)
	}
	if got := client.commandCount("load-key"); got != 1 {
		t.Fatalf("load-key calls = %d, want 1", got)
	}

	if err := driver.UnloadPrivateKey(context.Background(), "link-a"); err != nil {
		t.Fatalf("UnloadPrivateKey(link-a): %v", err)
	}
	if got := client.commandCount("unload-key"); got != 0 {
		t.Fatalf("unload-key calls after first reference = %d, want 0", got)
	}
	if err := driver.UnloadPrivateKey(context.Background(), "link-a"); err != nil {
		t.Fatalf("UnloadPrivateKey(link-a repeat): %v", err)
	}
	if err := driver.UnloadPrivateKey(context.Background(), "link-b"); err != nil {
		t.Fatalf("UnloadPrivateKey(link-b): %v", err)
	}
	if got := client.commandCount("unload-key"); got != 1 {
		t.Fatalf("unload-key calls after final reference = %d, want 1", got)
	}
}

func TestStrongSwanDriverUnloadPrivateKeyTreatsNotFoundAsSuccess(t *testing.T) {
	key, _, err := GenerateTransportKeyRecord(AlgorithmEd25519, time.Unix(1000, 0), 0)
	if err != nil {
		t.Fatalf("GenerateTransportKeyRecord: %v", err)
	}
	client := &privateKeyVICIClient{unloadErr: errors.New("VICI unload-key failed: key not found")}
	driver := &StrongSwanDriver{VICI: client}

	if err := driver.LoadPrivateKey(context.Background(), "link-a", key.PrivateKey, key.Algorithm); err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if err := driver.UnloadPrivateKey(context.Background(), "link-a"); err != nil {
		t.Fatalf("UnloadPrivateKey: %v", err)
	}
	if err := driver.UnloadPrivateKey(context.Background(), "link-a"); err != nil {
		t.Fatalf("UnloadPrivateKey repeat: %v", err)
	}
	if got := client.commandCount("unload-key"); got != 1 {
		t.Fatalf("unload-key calls = %d, want 1", got)
	}
}

func TestStrongSwanDriverRetriesPrivateKeyUnloadFailure(t *testing.T) {
	key, _, err := GenerateTransportKeyRecord(AlgorithmEd25519, time.Unix(1000, 0), 0)
	if err != nil {
		t.Fatalf("GenerateTransportKeyRecord: %v", err)
	}
	client := &privateKeyVICIClient{unloadErr: errors.New("VICI unavailable")}
	driver := &StrongSwanDriver{VICI: client}

	if err := driver.LoadPrivateKey(context.Background(), "link-a", key.PrivateKey, key.Algorithm); err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if err := driver.UnloadPrivateKey(context.Background(), "link-a"); err == nil {
		t.Fatal("UnloadPrivateKey unexpectedly succeeded")
	}
	client.mu.Lock()
	client.unloadErr = nil
	client.mu.Unlock()
	if err := driver.UnloadPrivateKey(context.Background(), "link-a"); err != nil {
		t.Fatalf("UnloadPrivateKey retry: %v", err)
	}
	if got := client.commandCount("unload-key"); got != 2 {
		t.Fatalf("unload-key calls = %d, want 2", got)
	}
}
