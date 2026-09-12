package ratelimit

import (
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/platform/clock"
)

func TestBurstThenThrottle(t *testing.T) {
	clk := clock.NewFixed(time.Unix(1_700_000_000, 0))
	l := NewLocal(clk)
	rule := Rule{Name: "t", Burst: 5, Period: time.Second}

	for i := 0; i < 5; i++ {
		if d := l.Allow("k", rule); !d.Allowed {
			t.Fatalf("request %d of the burst was rejected", i+1)
		}
	}
	d := l.Allow("k", rule)
	if d.Allowed {
		t.Fatal("the 6th request inside one period must be rejected")
	}
	if d.RetryAfter <= 0 || d.RetryAfter > time.Second {
		t.Fatalf("RetryAfter %v is not a sane hint", d.RetryAfter)
	}
}

// GCRA's defining property: capacity returns smoothly, not all at once on a
// window boundary. After one emission interval exactly one slot is free.
func TestLeaksContinuouslyNotInWindows(t *testing.T) {
	clk := clock.NewFixed(time.Unix(1_700_000_000, 0))
	l := NewLocal(clk)
	rule := Rule{Name: "t", Burst: 10, Period: time.Second} // 100ms per cell

	for i := 0; i < 10; i++ {
		l.Allow("k", rule)
	}
	if l.Allow("k", rule).Allowed {
		t.Fatal("bucket should be full")
	}
	clk.Advance(100 * time.Millisecond)
	if !l.Allow("k", rule).Allowed {
		t.Fatal("one cell should have drained after one emission interval")
	}
	if l.Allow("k", rule).Allowed {
		t.Fatal("only one cell should have drained")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	clk := clock.NewFixed(time.Unix(1_700_000_000, 0))
	l := NewLocal(clk)
	rule := Rule{Name: "t", Burst: 2, Period: time.Minute}
	for i := 0; i < 2; i++ {
		l.Allow("a", rule)
	}
	if l.Allow("a", rule).Allowed {
		t.Fatal("key a should be exhausted")
	}
	if !l.Allow("b", rule).Allowed {
		t.Fatal("key b must not be affected by key a")
	}
}

func TestRulesAreIndependentForSameKey(t *testing.T) {
	clk := clock.NewFixed(time.Unix(1_700_000_000, 0))
	l := NewLocal(clk)
	r1 := Rule{Name: "one", Burst: 1, Period: time.Minute}
	r2 := Rule{Name: "two", Burst: 1, Period: time.Minute}
	if !l.Allow("k", r1).Allowed || !l.Allow("k", r2).Allowed {
		t.Fatal("distinct rules must not share state")
	}
	if l.Allow("k", r1).Allowed {
		t.Fatal("rule one should now be exhausted")
	}
}

func TestAllowNChargesMultipleCells(t *testing.T) {
	clk := clock.NewFixed(time.Unix(1_700_000_000, 0))
	l := NewLocal(clk)
	rule := Rule{Name: "t", Burst: 10, Period: time.Second}
	if !l.AllowN("k", rule, 10).Allowed {
		t.Fatal("a 10-unit charge should fit an empty 10-burst bucket")
	}
	if l.Allow("k", rule).Allowed {
		t.Fatal("bucket should now be empty")
	}
}

// An attacker cycling keys must not grow memory without bound.
func TestSweepBoundsMemory(t *testing.T) {
	clk := clock.NewFixed(time.Unix(1_700_000_000, 0))
	l := NewLocal(clk)
	rule := Rule{Name: "t", Burst: 1, Period: time.Second}
	for i := 0; i < 50000; i++ {
		l.Allow(string(rune(i%1000))+"-"+time.Duration(i).String(), rule)
	}
	before := l.Size()
	clk.Advance(time.Hour)
	l.Sweep()
	if l.Size() != 0 {
		t.Fatalf("sweep left %d of %d entries behind", l.Size(), before)
	}
}

func TestConcurrentAllowIsRaceFree(t *testing.T) {
	l := NewLocal(clock.System())
	rule := Rule{Name: "t", Burst: 1000, Period: time.Second}
	done := make(chan struct{})
	for w := 0; w < 8; w++ {
		go func() {
			for i := 0; i < 5000; i++ {
				l.Allow("shared", rule)
			}
			done <- struct{}{}
		}()
	}
	for w := 0; w < 8; w++ {
		<-done
	}
}

func BenchmarkAllow(b *testing.B) {
	l := NewLocal(clock.System())
	rule := Rule{Name: "b", Burst: 1_000_000, Period: time.Second}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.Allow("key", rule)
		}
	})
}
