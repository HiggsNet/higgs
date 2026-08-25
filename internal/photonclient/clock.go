package photonclient

import "time"

// SystemClock is the production wall/monotonic clock adapter.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

func (SystemClock) NewTimer(after time.Duration) Timer {
	return systemTimer{timer: time.NewTimer(after)}
}

type systemTimer struct {
	timer *time.Timer
}

func (t systemTimer) C() <-chan time.Time            { return t.timer.C }
func (t systemTimer) Reset(after time.Duration) bool { return t.timer.Reset(after) }
func (t systemTimer) Stop() bool                     { return t.timer.Stop() }
