// Package outbox implements the transactional outbox pattern.
//
// The problem it solves: a handler that writes to the database and then
// publishes an event has two ways to be wrong. If the publish happens first and
// the transaction rolls back, the world hears about something that did not
// happen. If the write happens first and the process dies, the world never
// hears about something that did.
//
// The fix is to write the intent to publish in the SAME transaction as the
// state change, then move it out separately. Delivery is therefore at least
// once, never exactly once, so every consumer must be idempotent. The ledger's
// idempotency key and provider_webhook_events are what make that true here.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/logx"
	"github.com/muthu2201/market-place/internal/platform/metrics"
)

// Message is one queued publication.
type Message struct {
	ID            ids.UUID
	Topic         string
	AggregateType string
	AggregateID   string
	Payload       json.RawMessage
	Headers       map[string]string
	Attempts      int
	CreatedAt     time.Time
	// OrderingKey, when set, guarantees that messages sharing it are delivered
	// in insertion order: two updates to the same order cannot be reordered.
	OrderingKey string
}

// Topics are the published event names. They are constants so a typo is a
// compile error rather than a message nobody consumes.
const (
	TopicOrderPaid          = "order.paid"
	TopicOrderFulfilled     = "order.fulfilled"
	TopicOrderRefunded      = "order.refunded"
	TopicOrderCancelled     = "order.cancelled"
	TopicLicenseIssued      = "license.issued"
	TopicPaymentCaptured    = "payment.captured"
	TopicPaymentFailed      = "payment.failed"
	TopicTransferReleased   = "transfer.released"
	TopicChargebackOpened   = "chargeback.opened"
	TopicDisputeOpened      = "dispute.opened"
	TopicSellerKYCUpdated   = "seller.kyc_updated"
	TopicProductPublished   = "product.published"
	TopicProductFlagged     = "product.flagged"
	TopicAssetScanned       = "asset.scanned"
	TopicGrievanceReceived  = "grievance.received"
	TopicNotificationQueued = "notification.queued"
	TopicSettlementDue      = "settlement.due"
	TopicReconciliationDiff = "reconciliation.difference"
)

// Publish records the intent to publish. It takes a db.Tx so it is impossible
// to publish outside the transaction carrying the state change.
func Publish(ctx context.Context, tx db.Tx, m Message) (ids.UUID, error) {
	if m.Topic == "" || m.AggregateType == "" || m.AggregateID == "" {
		return ids.UUID{}, errors.New("outbox: topic, aggregate type and aggregate id are required")
	}
	if len(m.Payload) == 0 {
		m.Payload = json.RawMessage(`{}`)
	}
	id := m.ID
	if id.IsZero() {
		id = ids.NewUUIDv7()
	}
	headers := m.Headers
	if headers == nil {
		headers = map[string]string{}
	}
	if rid := logx.RequestID(ctx); rid != "" {
		headers["request_id"] = rid
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO outbox_messages (id, topic, aggregate_type, aggregate_id, payload, headers, ordering_key)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, m.Topic, m.AggregateType, m.AggregateID, m.Payload, headers, nullIfEmpty(m.OrderingKey),
	); err != nil {
		return ids.UUID{}, fmt.Errorf("outbox: publish %s: %w", m.Topic, err)
	}
	return id, nil
}

// PublishJSON marshals a payload and publishes it.
func PublishJSON(ctx context.Context, tx db.Tx, topic, aggregateType, aggregateID string, payload any, orderingKey string) (ids.UUID, error) {
	buf, err := json.Marshal(payload)
	if err != nil {
		return ids.UUID{}, fmt.Errorf("outbox: encode %s: %w", topic, err)
	}
	return Publish(ctx, tx, Message{
		Topic: topic, AggregateType: aggregateType, AggregateID: aggregateID,
		Payload: buf, OrderingKey: orderingKey,
	})
}

// Handler consumes one message. It MUST be idempotent: delivery is at least
// once, and a handler that succeeds but fails to acknowledge will be re-run.
type Handler func(ctx context.Context, m Message) error

// Dispatcher moves messages out of the outbox.
type Dispatcher struct {
	db       *db.DB
	handlers map[string][]Handler
	log      *slog.Logger
	m        *metrics.App
	workerID string

	batchSize   int
	maxAttempts int
	// baseBackoff grows exponentially per attempt, capped, so a failing
	// downstream is retried without becoming a hot loop.
	baseBackoff time.Duration
	maxBackoff  time.Duration
}

// DispatcherOptions configures the dispatcher.
type DispatcherOptions struct {
	DB          *db.DB
	Log         *slog.Logger
	Metrics     *metrics.App
	WorkerID    string
	BatchSize   int
	MaxAttempts int
}

func NewDispatcher(o DispatcherOptions) *Dispatcher {
	if o.BatchSize <= 0 {
		o.BatchSize = 100
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 12
	}
	if o.WorkerID == "" {
		o.WorkerID = ids.Correlation()
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Dispatcher{
		db: o.DB, handlers: map[string][]Handler{}, log: o.Log, m: o.Metrics,
		workerID: o.WorkerID, batchSize: o.BatchSize, maxAttempts: o.MaxAttempts,
		baseBackoff: 2 * time.Second, maxBackoff: 10 * time.Minute,
	}
}

// On registers a handler for a topic. Several handlers may share a topic; each
// is invoked and a failure in one does not prevent the others from running, but
// the message is only acknowledged when all have succeeded.
func (d *Dispatcher) On(topic string, h Handler) { d.handlers[topic] = append(d.handlers[topic], h) }

// Tick claims and processes one batch, returning how many were dispatched.
//
// Claiming uses SKIP LOCKED so that several workers can run concurrently
// without contending, and the claim is committed before handlers run so a
// crashed worker's messages return to the queue by lock expiry rather than
// being held forever.
func (d *Dispatcher) Tick(ctx context.Context) (int, error) {
	claimed, err := d.claim(ctx)
	if err != nil {
		return 0, err
	}
	if len(claimed) == 0 {
		return 0, nil
	}
	for _, m := range claimed {
		d.process(ctx, m)
	}
	return len(claimed), nil
}

func (d *Dispatcher) claim(ctx context.Context) ([]Message, error) {
	var out []Message
	err := d.db.InTx(ctx, db.TxOptions{Name: "outbox_claim"}, func(ctx context.Context, tx db.Tx) error {
		// The ordering-key guard is the subtle part: a message is only eligible
		// when no OLDER undispatched message shares its key, which preserves
		// per-aggregate order without serialising the whole queue.
		rows, err := tx.Query(ctx, `
			WITH claimable AS (
				SELECT m.id
				  FROM outbox_messages m
				 WHERE m.dispatched_at IS NULL
				   AND m.failed_at IS NULL
				   AND m.available_at <= now()
				   AND (m.locked_at IS NULL OR m.locked_at < now() - INTERVAL '5 minutes')
				   AND NOT EXISTS (
					   SELECT 1 FROM outbox_messages older
					    WHERE older.ordering_key IS NOT NULL
					      AND older.ordering_key = m.ordering_key
					      AND older.dispatched_at IS NULL
					      AND older.failed_at IS NULL
					      AND older.id < m.id
				   )
				 ORDER BY m.available_at, m.id
				 LIMIT $1
				 FOR UPDATE SKIP LOCKED
			)
			UPDATE outbox_messages o
			   SET locked_at = now(), locked_by = $2, attempts = o.attempts + 1
			  FROM claimable c
			 WHERE o.id = c.id
			 RETURNING o.id, o.topic, o.aggregate_type, o.aggregate_id, o.payload,
			           o.headers, o.attempts, o.created_at, COALESCE(o.ordering_key, '')`,
			d.batchSize, d.workerID)
		if err != nil {
			return fmt.Errorf("outbox: claim: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var m Message
			if err := rows.Scan(&m.ID, &m.Topic, &m.AggregateType, &m.AggregateID,
				&m.Payload, &m.Headers, &m.Attempts, &m.CreatedAt, &m.OrderingKey); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

func (d *Dispatcher) process(ctx context.Context, m Message) {
	handlers := d.handlers[m.Topic]
	if len(handlers) == 0 {
		// An unconsumed topic is acknowledged rather than retried forever. It
		// is recorded so that a missing subscription is visible in metrics
		// instead of silently accumulating a backlog.
		d.log.WarnContext(ctx, "outbox message has no handler",
			slog.String("topic", m.Topic), slog.String("id", m.ID.String()))
		if d.m != nil {
			d.m.OutboxFailures.Inc(m.Topic, "no_handler")
		}
		d.ack(ctx, m)
		return
	}

	var firstErr error
	for _, h := range handlers {
		if err := h(ctx, m); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		d.ack(ctx, m)
		if d.m != nil {
			d.m.OutboxDispatched.Inc(m.Topic)
		}
		return
	}
	d.nack(ctx, m, firstErr)
}

func (d *Dispatcher) ack(ctx context.Context, m Message) {
	if _, err := d.db.Exec(context.WithoutCancel(ctx),
		`UPDATE outbox_messages SET dispatched_at = now(), locked_at = NULL, locked_by = NULL WHERE id = $1`,
		m.ID); err != nil {
		d.log.ErrorContext(ctx, "outbox: acknowledge failed",
			slog.String("id", m.ID.String()), slog.String("error", err.Error()))
	}
}

func (d *Dispatcher) nack(ctx context.Context, m Message, cause error) {
	backoff := d.backoffFor(m.Attempts)
	dead := m.Attempts >= d.maxAttempts

	d.log.ErrorContext(ctx, "outbox dispatch failed",
		slog.String("topic", m.Topic), slog.String("id", m.ID.String()),
		slog.Int("attempt", m.Attempts), slog.Bool("dead_letter", dead),
		slog.String("error", cause.Error()))

	reason := "handler_error"
	if dead {
		reason = "dead_letter"
	}
	if d.m != nil {
		d.m.OutboxFailures.Inc(m.Topic, reason)
	}

	if dead {
		// A dead letter is kept, not dropped. It is the operator's queue.
		if _, err := d.db.Exec(context.WithoutCancel(ctx), `
			UPDATE outbox_messages
			   SET failed_at = now(), locked_at = NULL, locked_by = NULL, last_error = $2
			 WHERE id = $1`, m.ID, truncate(cause.Error(), 2000)); err != nil {
			d.log.ErrorContext(ctx, "outbox: dead-letter failed", slog.String("error", err.Error()))
		}
		return
	}
	if _, err := d.db.Exec(context.WithoutCancel(ctx), `
		UPDATE outbox_messages
		   SET available_at = now() + $2::interval, locked_at = NULL, locked_by = NULL, last_error = $3
		 WHERE id = $1`, m.ID, backoff.String(), truncate(cause.Error(), 2000)); err != nil {
		d.log.ErrorContext(ctx, "outbox: reschedule failed", slog.String("error", err.Error()))
	}
}

func (d *Dispatcher) backoffFor(attempt int) time.Duration {
	b := d.baseBackoff
	for i := 1; i < attempt && b < d.maxBackoff; i++ {
		b *= 2
	}
	if b > d.maxBackoff {
		b = d.maxBackoff
	}
	return b
}

// Pending reports the current backlog, for the readiness probe and alerting.
func (d *Dispatcher) Pending(ctx context.Context) (int, error) {
	var n int
	err := d.db.QueryRow(ctx,
		`SELECT count(*) FROM outbox_messages WHERE dispatched_at IS NULL AND failed_at IS NULL`).Scan(&n)
	return n, err
}

// DeadLettered reports messages that exhausted their attempts.
func (d *Dispatcher) DeadLettered(ctx context.Context) (int, error) {
	var n int
	err := d.db.QueryRow(ctx, `SELECT count(*) FROM outbox_messages WHERE failed_at IS NOT NULL`).Scan(&n)
	return n, err
}

// Replay returns a dead-lettered message to the queue, for use after the
// downstream cause has been fixed.
func (d *Dispatcher) Replay(ctx context.Context, id ids.UUID) error {
	tag, err := d.db.Exec(ctx, `
		UPDATE outbox_messages
		   SET failed_at = NULL, attempts = 0, available_at = now(), last_error = NULL
		 WHERE id = $1 AND failed_at IS NOT NULL`, id)
	if err != nil {
		return fmt.Errorf("outbox: replay: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("outbox: %s is not dead-lettered", id)
	}
	return nil
}

// Run polls until the context is cancelled. It sleeps only when the queue is
// empty, so a burst is drained at full speed rather than one batch per tick.
func (d *Dispatcher) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = time.Second
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		n, err := d.Tick(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			d.log.ErrorContext(ctx, "outbox tick failed", slog.String("error", err.Error()))
		}
		if d.m != nil {
			if pending, err := d.Pending(ctx); err == nil {
				d.m.OutboxPending.Set(float64(pending))
			}
		}
		wait := interval
		if n >= d.batchSize {
			wait = 0 // more work is waiting; do not idle
		}
		timer.Reset(wait)
	}
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
