package main

import (
	"context"
	"testing"
	"time"

	corehost "github.com/HiggsNet/photon/pkg/core/host"
)

func TestForwardHealthCompletionsUsesHostRuntimeQueue(t *testing.T) {
	runtime := corehost.NewRuntime(corehost.NewClock(nil), 1)
	defer runtime.Stop()
	d := &DaemonService{hostRuntime: runtime}
	updates := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go d.forwardHealthCompletions(ctx, updates)
	updates <- struct{}{}
	select {
	case event := <-runtime.Events():
		completion, ok := event.(corehost.Completion)
		if !ok {
			t.Fatalf("event = %#v, want host completion", event)
		}
		if completion.Namespace != daemonRuntimeNamespace || completion.Owner != daemonCompletionHealthOwner || completion.Key != daemonCompletionHealth {
			t.Fatalf("completion = %#v", completion)
		}
	case <-time.After(time.Second):
		t.Fatal("health completion was not forwarded")
	}
}

func TestScheduleDaemonTimerUsesHostRuntimeNamespace(t *testing.T) {
	runtime := corehost.NewRuntime(corehost.NewClock(nil), 1)
	defer runtime.Stop()
	d := &DaemonService{hostRuntime: runtime}
	if err := d.scheduleDaemonTimer(daemonTimerRouting, time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-runtime.Events():
		fired, ok := event.(corehost.TimerFired)
		if !ok || fired.ID.Namespace != daemonRuntimeNamespace || fired.ID.Owner != daemonTimerOwner || fired.ID.Key != daemonTimerRouting {
			t.Fatalf("timer event = %#v", event)
		}
		if !runtime.AcceptTimer(fired) {
			t.Fatal("daemon timer was not accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("daemon timer did not fire")
	}
}

func TestScheduleDaemonTimerCancelsDisabledFirewallInterval(t *testing.T) {
	runtime := corehost.NewRuntime(corehost.NewClock(nil), 1)
	defer runtime.Stop()
	d := &DaemonService{hostRuntime: runtime}
	id := corehost.TimerID{Namespace: daemonRuntimeNamespace, Owner: daemonTimerOwner, Key: daemonTimerFirewall}
	if err := d.scheduleDaemonTimer(daemonTimerFirewall, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := d.scheduleDaemonTimer(daemonTimerFirewall, nextFirewallReconcileTime(time.Now(), 0)); err != nil {
		t.Fatal(err)
	}
	if runtime.AcceptTimer(corehost.TimerFired{ID: id, Generation: 1}) {
		t.Fatal("cancelled firewall timer generation was accepted")
	}
}
