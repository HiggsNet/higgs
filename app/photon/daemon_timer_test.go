package main

import (
	"testing"
	"time"

	corehost "github.com/HiggsNet/photon/pkg/core/host"
)

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
		if !ok || fired.ID.Namespace != daemonTimerNamespace || fired.ID.Owner != daemonTimerOwner || fired.ID.Key != daemonTimerRouting {
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
	id := corehost.TimerID{Namespace: daemonTimerNamespace, Owner: daemonTimerOwner, Key: daemonTimerFirewall}
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
