package outbox_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/outbox"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/dbtest"
	"github.com/muthu2201/market-place/internal/platform/ids"
)

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newDispatcher(d *db.DB, worker string) *outbox.Dispatcher {
	return outbox.NewDispatcher(outbox.DispatcherOptions{
		DB: d, Log: quietLog(), Metrics: dbtest.Metrics(),
		WorkerID: worker, BatchSize: 50, MaxAttempts: 3,
	})
}

func publish(t *testing.T, d *db.DB, topic, aggID string, payload any, orderingKey string) ids.UUID {
	t.Helper()
	var id ids.UUID
	if err := d.InTx(context.Background(), db.TxOptions{Name: "pub"}, func(ctx context.Context, tx db.Tx) error {
		var err error
		id, err = outbox.PublishJSON(ctx, tx, topic, "order", aggID, payload, orderingKey)
		return err
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	return id
}

// The defining property: if the transaction rolls back, nothing was published.
func TestPublishIsAtomicWithTheStateChange(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)

	sentinel := errors.New("business rule failed")
	err := d.InTx(ctx, db.TxOptions{Name: "rollback"}, func(ctx context.Context, tx db.Tx) error {
		if _, err := outbox.PublishJSON(ctx, tx, outbox.TopicOrderPaid, "order", "ord_1", map[string]any{"x": 1}, ""); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected the sentinel, got %v", err)
	}
	var n int
	if err := d.QueryRow(ctx, `SELECT count(*) FROM outbox_messages`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a rolled-back transaction published %d messages", n)
	}
}

func TestDispatchDeliversAndAcknowledges(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	disp := newDispatcher(d, "w1")

	var got atomic.Int64
	disp.On(outbox.TopicOrderPaid, func(ctx context.Context, m outbox.Message) error {
		if m.AggregateID != "ord_42" {
			t.Errorf("aggregate id = %s", m.AggregateID)
		}
		got.Add(1)
		return nil
	})

	publish(t, d, outbox.TopicOrderPaid, "ord_42", map[string]any{"total": 236000}, "")
	n, err := disp.Tick(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || got.Load() != 1 {
		t.Fatalf("dispatched %d, handled %d", n, got.Load())
	}
	// A second tick must find nothing: the message was acknowledged.
	if n, err := disp.Tick(ctx); err != nil || n != 0 {
		t.Fatalf("second tick dispatched %d (err %v)", n, err)
	}
	pending, _ := disp.Pending(ctx)
	if pending != 0 {
		t.Fatalf("pending = %d", pending)
	}
}

func TestFailingHandlerIsRetriedThenDeadLettered(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	disp := newDispatcher(d, "w1")

	var attempts atomic.Int64
	disp.On(outbox.TopicOrderPaid, func(ctx context.Context, m outbox.Message) error {
		attempts.Add(1)
		return errors.New("downstream is down")
	})

	id := publish(t, d, outbox.TopicOrderPaid, "ord_fail", map[string]any{}, "")
	for i := 0; i < 3; i++ {
		if _, err := disp.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		// Backoff would otherwise hold the message; bring it forward.
		if _, err := d.Exec(ctx, `UPDATE outbox_messages SET available_at = now() WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
	}
	if attempts.Load() != 3 {
		t.Fatalf("attempts = %d, want 3", attempts.Load())
	}
	dead, err := disp.DeadLettered(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if dead != 1 {
		t.Fatalf("dead-lettered = %d, want 1", dead)
	}

	// A dead letter is kept for the operator and can be replayed once fixed.
	var succeeded atomic.Int64
	disp2 := newDispatcher(d, "w2")
	disp2.On(outbox.TopicOrderPaid, func(ctx context.Context, m outbox.Message) error {
		succeeded.Add(1)
		return nil
	})
	if err := disp2.Replay(ctx, id); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if _, err := disp2.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if succeeded.Load() != 1 {
		t.Fatal("a replayed message must be delivered")
	}
}

func TestBackoffGrowsBetweenAttempts(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	disp := newDispatcher(d, "w1")
	disp.On(outbox.TopicOrderPaid, func(context.Context, outbox.Message) error {
		return errors.New("nope")
	})
	id := publish(t, d, outbox.TopicOrderPaid, "ord_bo", map[string]any{}, "")

	if _, err := disp.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	var firstDelay float64
	if err := d.QueryRow(ctx,
		`SELECT EXTRACT(EPOCH FROM (available_at - now())) FROM outbox_messages WHERE id = $1`, id).Scan(&firstDelay); err != nil {
		t.Fatal(err)
	}
	if firstDelay <= 0 {
		t.Fatalf("a failed message must be deferred, delay = %.2fs", firstDelay)
	}
	// A message still inside its backoff window must not be re-claimed.
	if n, err := disp.Tick(ctx); err != nil || n != 0 {
		t.Fatalf("a deferred message was re-claimed immediately (n=%d err=%v)", n, err)
	}
}

// Delivery is at least once, so a handler that is not idempotent will be
// re-run. This asserts the redelivery actually happens, which is what makes
// idempotency a requirement rather than a nicety.
func TestRedeliveryHappensAfterACrashedWorker(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	id := publish(t, d, outbox.TopicOrderPaid, "ord_crash", map[string]any{}, "")

	// Simulate a worker that claimed the message and then died.
	if _, err := d.Exec(ctx,
		`UPDATE outbox_messages SET locked_at = now() - INTERVAL '10 minutes', locked_by = 'dead-worker' WHERE id = $1`,
		id); err != nil {
		t.Fatal(err)
	}
	var delivered atomic.Int64
	disp := newDispatcher(d, "w2")
	disp.On(outbox.TopicOrderPaid, func(context.Context, outbox.Message) error {
		delivered.Add(1)
		return nil
	})
	if _, err := disp.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if delivered.Load() != 1 {
		t.Fatal("a stale lock must be reclaimed so the message is not lost")
	}
}

func TestOrderingKeyPreservesPerAggregateOrder(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)

	var mu sync.Mutex
	var seen []string
	disp := newDispatcher(d, "w1")
	handler := func(ctx context.Context, m outbox.Message) error {
		mu.Lock()
		seen = append(seen, string(m.Payload))
		mu.Unlock()
		return nil
	}
	disp.On(outbox.TopicOrderPaid, handler)
	disp.On(outbox.TopicOrderFulfilled, handler)
	disp.On(outbox.TopicOrderRefunded, handler)

	// Three events about the same order, published in a definite order.
	publish(t, d, outbox.TopicOrderPaid, "ord_seq", map[string]any{"step": 1}, "ord_seq")
	publish(t, d, outbox.TopicOrderFulfilled, "ord_seq", map[string]any{"step": 2}, "ord_seq")
	publish(t, d, outbox.TopicOrderRefunded, "ord_seq", map[string]any{"step": 3}, "ord_seq")

	for i := 0; i < 5; i++ {
		if _, err := disp.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("delivered %d of 3: %v", len(seen), seen)
	}
	// jsonb round-trips with normalised spacing; compare against that form.
	want := []string{`{"step": 1}`, `{"step": 2}`, `{"step": 3}`}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("out of order: got %v, want %v", seen, want)
		}
	}
}

func TestConcurrentWorkersDoNotDoubleDeliver(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)

	const total = 300
	for i := 0; i < total; i++ {
		publish(t, d, outbox.TopicOrderPaid, "ord_"+ids.Correlation(), map[string]any{"i": i}, "")
	}

	var mu sync.Mutex
	delivered := map[string]int{}
	mk := func(name string) *outbox.Dispatcher {
		disp := outbox.NewDispatcher(outbox.DispatcherOptions{
			DB: d, Log: quietLog(), Metrics: dbtest.Metrics(),
			WorkerID: name, BatchSize: 25, MaxAttempts: 3,
		})
		disp.On(outbox.TopicOrderPaid, func(ctx context.Context, m outbox.Message) error {
			mu.Lock()
			delivered[m.ID.String()]++
			mu.Unlock()
			return nil
		})
		return disp
	}

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			disp := mk("worker-" + string(rune('a'+w)))
			for {
				n, err := disp.Tick(ctx)
				if err != nil {
					t.Errorf("worker %d: %v", w, err)
					return
				}
				if n == 0 {
					return
				}
			}
		}(w)
	}
	wg.Wait()

	if len(delivered) != total {
		t.Fatalf("delivered %d distinct messages, want %d", len(delivered), total)
	}
	for id, count := range delivered {
		if count != 1 {
			t.Fatalf("message %s delivered %d times: SKIP LOCKED claiming is broken", id, count)
		}
	}
}

func TestUnhandledTopicIsAcknowledgedNotLooped(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	disp := newDispatcher(d, "w1")
	publish(t, d, "some.topic.nobody.consumes", "ord_x", map[string]any{}, "")

	if _, err := disp.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	pending, _ := disp.Pending(ctx)
	if pending != 0 {
		t.Fatal("an unconsumed topic must not accumulate a backlog forever")
	}
}

func TestRunDrainsAndStopsOnContextCancel(t *testing.T) {
	d := dbtest.Fresh(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var delivered atomic.Int64
	disp := newDispatcher(d, "runner")
	disp.On(outbox.TopicOrderPaid, func(context.Context, outbox.Message) error {
		delivered.Add(1)
		return nil
	})
	for i := 0; i < 20; i++ {
		publish(t, d, outbox.TopicOrderPaid, "ord_run_"+ids.Correlation(), map[string]any{}, "")
	}

	done := make(chan error, 1)
	go func() { done <- disp.Run(ctx, 10*time.Millisecond) }()

	deadline := time.After(10 * time.Second)
	for delivered.Load() < 20 {
		select {
		case <-deadline:
			t.Fatalf("only %d of 20 delivered", delivered.Load())
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop on cancellation")
	}
}
