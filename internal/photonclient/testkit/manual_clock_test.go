package testkit

import (
	"testing"
	"time"
)

func TestManualClockTimerAdvanceResetAndStop(t *testing.T) {
	start := time.Unix(100, 0)
	clock := NewManualClock(start)
	timer := clock.NewTimer(10 * time.Second)

	clock.Advance(9 * time.Second)
	select {
	case <-timer.C():
		t.Fatal("timer fired early")
	default:
	}
	clock.Advance(time.Second)
	select {
	case got := <-timer.C():
		if !got.Equal(start.Add(10 * time.Second)) {
			t.Fatalf("timer value = %s", got)
		}
	default:
		t.Fatal("timer did not fire")
	}

	if active := timer.Reset(5 * time.Second); active {
		t.Fatal("Reset returned active after timer fired")
	}
	if stopped := timer.Stop(); !stopped {
		t.Fatal("Stop returned false for active reset timer")
	}
	clock.Advance(5 * time.Second)
	select {
	case <-timer.C():
		t.Fatal("stopped timer fired")
	default:
	}
}
