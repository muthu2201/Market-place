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

func TestUUIDRoundTripAndTime(t *testing.T) {
	u := NewUUIDv7()
	back, err := ParseUUID(u.String())
	if err != nil || back != u {
		t.Fatalf("round trip failed: %v %s %s", err, u, back)
	}
	if d := time.Since(u.Time()); d < 0 || d > time.Minute {
		t.Fatalf("embedded time is off by %v", d)
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
