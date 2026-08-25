package main

import (
	"testing"
	"time"
)

func TestNextTimerWait(t *testing.T) {
	now := time.Unix(1000, 0)
	d := &DaemonService{Sync: &SyncRuntime{App: &Runtime{Clock: func() time.Time { return now }}}}
	if wait := d.nextTimerWait(now.Add(time.Second), now.Add(2*time.Second)); wait != time.Second {
		t.Fatalf("nextTimerWait = %v, want 1s", wait)
	}
	if wait := d.nextTimerWait(now.Add(-time.Second), now.Add(time.Second)); wait != 0 {
		t.Fatalf("nextTimerWait for due deadline = %v, want 0", wait)
	}
	if wait := d.nextTimerWait(time.Time{}, time.Time{}); wait != 24*time.Hour {
		t.Fatalf("nextTimerWait with no deadlines = %v, want 24h", wait)
	}
}
