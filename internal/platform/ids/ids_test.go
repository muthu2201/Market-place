package ids

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUUIDv7VersionVariantAndOrdering(t *testing.T) {
	prev := NewUUIDv7()
	if prev[6]>>4 != 7 {
		t.Fatalf("version nibble = %d, want 7", prev[6]>>4)
	}
	if prev[8]&0xC0 != 0x80 {
		t.Fatalf("variant bits = %02x, want 10xxxxxx", prev[8])
	}
	for i := 0; i < 200000; i++ {
		u := NewUUIDv7()
		if strings.Compare(u.String(), prev.String()) <= 0 {
			t.Fatalf("UUIDv7 not strictly increasing at %d: %s <= %s", i, u, prev)
		}
		prev = u
	}
}

func TestUUIDv7ConcurrentUniqueness(t *testing.T) {
	const workers, each = 8, 20000
	var mu sync.Mutex
	seen := make(map[UUID]struct{}, workers*each)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]UUID, each)
			for i := range local {
				local[i] = NewUUIDv7()
			}
			mu.Lock()
			defer mu.Unlock()
			for _, u := range local {
				if _, dup := seen[u]; dup {
					t.Errorf("duplicate UUID %s", u)
					return
				}
				seen[u] = struct{}{}
			}
		}()
	}
	wg.Wait()
}

// The forward drift implied by strict monotonicity is bounded, and it is
// self-correcting: once generation drops below 4,096 per millisecond the clock
// catches up. Both properties are asserted here so the documented guarantee
// cannot silently regress.
func TestUUIDv7DriftIsBoundedAndSelfCorrecting(t *testing.T) {
	const burst = 100_000

	// Drift INTRODUCED by this burst is what the bound governs. Measuring from
	// wall-clock zero would also count drift left over from earlier tests in
	// this binary, which is a different quantity.
	first := NewUUIDv7()
	startReal := time.Now()
	var last UUID
	for i := 0; i < burst; i++ {
		last = NewUUIDv7()
	}
	realElapsed := time.Since(startReal)
	embeddedElapsed := last.Time().Sub(first.Time())

	introduced := embeddedElapsed - realElapsed
	if introduced < 0 {
		introduced = 0
	}
	maxDrift := time.Duration(burst/4096+2) * time.Millisecond
	if introduced > maxDrift {
		t.Fatalf("this burst introduced %v of drift, above the documented bound of %v", introduced, maxDrift)
	}

	// Self-correction: after a pause longer than any accumulated drift, the
	// embedded timestamp tracks the wall clock again.
	time.Sleep(200 * time.Millisecond)
	if d := time.Since(NewUUIDv7().Time()); d < -5*time.Millisecond {
		t.Fatalf("the generator did not catch up after a pause: still %v ahead", -d)
	}
}

func TestUUIDRoundTripAndTime(t *testing.T) {
	u := NewUUIDv7()
	back, err := ParseUUID(u.String())
	if err != nil || back != u {
		t.Fatalf("round trip failed: %v %s %s", err, u, back)
	}
	// The embedded timestamp may run slightly ahead of the wall clock when an
	// earlier test burned through a millisecond's 4,096-identifier budget; the
	// generator borrows from the next millisecond to keep ordering strict.
	// Both directions are bounded.
	if d := time.Since(u.Time()); d < -time.Second || d > time.Minute {
		t.Fatalf("embedded time is off by %v, outside the documented bound", d)
	}
	if _, err := ParseUUID("not-a-uuid"); err == nil {
		t.Fatal("expected parse failure")
	}
}

func TestPublicIDShapeAndPrefix(t *testing.T) {
	id := NewPublic(PrefixProduct)
	if !strings.HasPrefix(id, "prd_") || len(id) != 30 {
		t.Fatalf("unexpected public id %q", id)
	}
	if !ValidPublic(id) {
		t.Fatalf("%q should validate", id)
	}
	if _, err := ParsePublic(PrefixProduct, id); err != nil {
		t.Fatalf("ParsePublic: %v", err)
	}
	if _, err := ParsePublic(PrefixOrder, id); err == nil {
		t.Fatal("prefix confusion must be rejected")
	}
	for _, bad := range []string{"", "prd_", "prd", "_ABC", "prd_TOOSHORT", "prd_" + strings.Repeat("!", 26)} {
		if _, err := ParsePublic(PrefixProduct, bad); err == nil {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}

func TestPublicIDsDoNotCollide(t *testing.T) {
	seen := make(map[string]struct{}, 200000)
	for i := 0; i < 200000; i++ {
		id := NewPublic(PrefixOrder)
		if _, dup := seen[id]; dup {
			t.Fatalf("collision at %d: %s", i, id)
		}
		seen[id] = struct{}{}
	}
}

func BenchmarkNewUUIDv7(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NewUUIDv7()
	}
}
