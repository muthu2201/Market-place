// Package clock makes time injectable so that expiry, rate limiting, decay and
// settlement windows can be tested deterministically instead of with sleeps.
package clock

import (
	"sync"
	"time"
)

// Clock is the only source of wall time the application may read.
type Clock interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

type systemClock struct{}

// System reads real UTC time.
func System() Clock { return systemClock{} }

func (systemClock) Now() time.Time                  { return time.Now().UTC() }
func (systemClock) Since(t time.Time) time.Duration { return time.Since(t) }

// Fixed is a controllable clock for tests.
type Fixed struct {
	mu sync.RWMutex
	t  time.Time
}

func NewFixed(t time.Time) *Fixed { return &Fixed{t: t.UTC()} }

func (f *Fixed) Now() time.Time {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.t
}

func (f *Fixed) Since(t time.Time) time.Duration { return f.Now().Sub(t) }

// Advance moves the fixed clock forward.
func (f *Fixed) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

// Set jumps the fixed clock to an absolute instant.
func (f *Fixed) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = t.UTC()
}
