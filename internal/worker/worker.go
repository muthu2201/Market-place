// Package worker runs everything that must happen outside a request.
//
// Two distinct mechanisms live here and they solve different problems:
//
//   - The outbox dispatcher moves events that were written atomically with a
//     state change. It exists so a domain change and its announcement cannot
//     disagree.
//   - Scheduled tasks run on a clock: releasing settlements whose protection
//     window has closed, rolling up ledger balances, sending queued mail,
//     expiring download grants, watching grievance deadlines and verifying the
//     audit chain.
//
// Every task is idempotent and safe to run on several replicas at once, because
// a task that assumes it is the only one running breaks the first time you
// scale out.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/muthu2201/market-place/internal/app"
	"github.com/muthu2201/market-place/internal/outbox"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/mail"
)

// Worker owns the background loops.
type Worker struct {
	app        *app.App
	log        *slog.Logger
	dispatcher *outbox.Dispatcher
	mailer     mail.Sender
	id         string
}

// New builds the worker and registers its outbox subscriptions.
func New(a *app.App, mailer mail.Sender) *Worker {
	id := ids.Correlation()
	log := a.Log.With(slog.String("component", "worker"), slog.String("worker_id", id))

	w := &Worker{
		app: a, log: log, mailer: mailer, id: id,
		dispatcher: outbox.NewDispatcher(outbox.DispatcherOptions{
			DB: a.DB, Log: log, Metrics: a.Metrics, WorkerID: id,
			BatchSize: a.Config.Worker.OutboxBatchSize, MaxAttempts: a.Config.Worker.MaxAttempts,
		}),
	}
	w.subscribe()
	return w
}

// Dispatcher exposes the outbox dispatcher for tests and for operational tools.
func (w *Worker) Dispatcher() *outbox.Dispatcher { return w.dispatcher }

// subscribe registers the outbox consumers.
//
// Every handler is idempotent, because outbox delivery is at least once. A
// handler that would be wrong if run twice is a bug, not a tuning problem.
func (w *Worker) subscribe() {
	w.dispatcher.On(outbox.TopicOrderPaid, func(ctx context.Context, m outbox.Message) error {
		return w.queueOrderMail(ctx, m, "order_receipt")
	})
	w.dispatcher.On(outbox.TopicOrderFulfilled, func(ctx context.Context, m outbox.Message) error {
		return w.queueOrderMail(ctx, m, "order_fulfilled")
	})
	w.dispatcher.On(outbox.TopicOrderRefunded, func(ctx context.Context, m outbox.Message) error {
		return w.queueOrderMail(ctx, m, "order_refunded")
	})
	w.dispatcher.On(outbox.TopicPaymentFailed, func(ctx context.Context, m outbox.Message) error {
		return w.queueOrderMail(ctx, m, "payment_failed")
	})
	w.dispatcher.On(outbox.TopicLicenseIssued, func(ctx context.Context, m outbox.Message) error {
		w.log.InfoContext(ctx, "licence issued", slog.String("license", m.AggregateID))
		return nil
	})
	w.dispatcher.On(outbox.TopicChargebackOpened, func(ctx context.Context, m outbox.Message) error {
		// A chargeback carries an externally imposed deadline, so this is a
		// warning that is expected to page someone.
		w.log.WarnContext(ctx, "chargeback opened: the representment deadline is set by the card network",
			slog.String("order", m.AggregateID), slog.String("detail", string(m.Payload)))
		return nil
	})
	w.dispatcher.On(outbox.TopicTransferReleased, func(ctx context.Context, m outbox.Message) error {
		w.log.InfoContext(ctx, "settlement released", slog.String("order", m.AggregateID))
		return nil
	})
	w.dispatcher.On(outbox.TopicSellerKYCUpdated, func(ctx context.Context, m outbox.Message) error {
		w.log.InfoContext(ctx, "seller provider status changed", slog.String("seller", m.AggregateID))
		return nil
	})
}

// queueOrderMail is written so a repeated delivery finds the notification
// already present rather than queueing a second copy.
func (w *Worker) queueOrderMail(ctx context.Context, m outbox.Message, template string) error {
	_, err := w.app.DB.Exec(ctx, `
		INSERT INTO notifications (id, public_id, user_id, channel, template, variables, category)
		SELECT $1, $2, o.buyer_id, 'email', $3,
		       jsonb_build_object('order_number', o.order_number, 'order_id', o.public_id,
		                          'total_minor', o.grand_total_minor, 'currency', o.currency),
		       'transactional'
		  FROM orders o
		 WHERE o.public_id = $4
		   AND NOT EXISTS (
		     SELECT 1 FROM notifications n
		      WHERE n.user_id = o.buyer_id AND n.template = $3
		        AND n.variables->>'order_id' = o.public_id)`,
		ids.NewUUIDv7(), ids.NewPublic(ids.PrefixNotification), template, m.AggregateID)
	if err != nil {
		return fmt.Errorf("worker: queue %s: %w", template, err)
	}
	return nil
}

// Task is one scheduled unit of work.
type Task struct {
	Name  string
	Every time.Duration
	Run   func(ctx context.Context) (string, error)
	// Jitter spreads replicas so several workers do not fire the same task at
	// the same instant.
	Jitter time.Duration
}

// Tasks returns the schedule.
func (w *Worker) Tasks() []Task {
	return []Task{
		{
			Name: "release_due_settlements", Every: time.Minute, Jitter: 10 * time.Second,
			Run: func(ctx context.Context) (string, error) {
				res, err := w.app.Orders.ReleaseDueSettlements(ctx, 200)
				if err != nil || res.Considered == 0 {
					return "", err
				}
				return fmt.Sprintf("considered=%d released=%d held=%d failed=%d reasons=%v",
					res.Considered, res.Released, res.Held, res.Failed, res.HeldReasons), nil
			},
		},
		{
			Name: "complete_protected_orders", Every: 5 * time.Minute, Jitter: 30 * time.Second,
			Run: func(ctx context.Context) (string, error) {
				window := time.Duration(w.app.Config.Payments.SettlementHoldDays) * 24 * time.Hour
				n, err := w.app.Orders.CompleteProtectedOrders(ctx, window, 500)
				if err != nil || n == 0 {
					return "", err
				}
				return fmt.Sprintf("completed=%d", n), nil
			},
		},
		{
			Name: "ledger_rollup", Every: 2 * time.Minute, Jitter: 15 * time.Second,
			Run: func(ctx context.Context) (string, error) {
				var n int
				err := w.app.DB.InTx(ctx, db.TxOptions{Name: "ledger_rollup"}, func(ctx context.Context, tx db.Tx) error {
					var err error
					n, err = w.app.Ledger.Rollup(ctx, tx)
					return err
				})
				if err != nil || n == 0 {
					return "", err
				}
				return fmt.Sprintf("accounts=%d", n), nil
			},
		},
		{
			Name: "rollup_turnover", Every: time.Minute, Jitter: 20 * time.Second,
			Run: func(ctx context.Context) (string, error) {
				var n int
				if err := w.app.DB.QueryRow(ctx, `SELECT rollup_turnover()`).Scan(&n); err != nil {
					return "", fmt.Errorf("worker: rollup turnover: %w", err)
				}
				if n == 0 {
					return "", nil
				}
				return fmt.Sprintf("rows=%d", n), nil
			},
		},
		{
			Name: "verify_trial_balance", Every: 5 * time.Minute, Jitter: 45 * time.Second,
			Run: func(ctx context.Context) (string, error) {
				// The most important invariant in the system: if this fails,
				// something has bypassed the ledger's balance rule.
				return "", w.app.Ledger.AssertBalanced(ctx, w.app.DB)
			},
		},
		{
			Name: "verify_audit_chain", Every: time.Hour, Jitter: 5 * time.Minute,
			Run: func(ctx context.Context) (string, error) {
				brk, err := w.app.Audit.Verify(ctx, w.app.DB, 0)
				if err != nil {
					return "", err
				}
				if brk != nil {
					return "", fmt.Errorf("AUDIT CHAIN BROKEN at sequence %d: %s", brk.Seq, brk.Reason)
				}
				return "", nil
			},
		},
		{Name: "send_queued_mail", Every: 15 * time.Second, Jitter: 3 * time.Second, Run: w.sendQueuedMail},
		{
			// Work, as distinct from the outbox's announcements: slow, retried
			// with backoff, and claimed SKIP LOCKED so one long scan never
			// blocks the queue behind it.
			Name: "run_jobs", Every: 5 * time.Second, Jitter: 2 * time.Second, Run: w.runJobs,
		},
		{
			Name: "expire_download_grants", Every: 10 * time.Minute, Jitter: time.Minute,
			Run: func(ctx context.Context) (string, error) {
				n, err := w.app.Delivery.ExpireGrants(ctx, 24*time.Hour)
				if err != nil || n == 0 {
					return "", err
				}
				return fmt.Sprintf("removed=%d", n), nil
			},
		},
		{Name: "expire_stale_orders", Every: 5 * time.Minute, Jitter: 30 * time.Second, Run: w.expireStaleOrders},
		{Name: "grievance_sla_watch", Every: 10 * time.Minute, Jitter: time.Minute, Run: w.grievanceSLAWatch},
		{
			Name: "purge_expired_idempotency_keys", Every: time.Hour, Jitter: 10 * time.Minute,
			Run: func(ctx context.Context) (string, error) {
				tag, err := w.app.DB.Exec(ctx, `DELETE FROM idempotency_keys WHERE expires_at < now()`)
				if err != nil || tag.RowsAffected() == 0 {
					return "", err
				}
				return fmt.Sprintf("removed=%d", tag.RowsAffected()), nil
			},
		},
		{
			Name: "prune_login_attempts", Every: 6 * time.Hour, Jitter: 15 * time.Minute,
			Run: func(ctx context.Context) (string, error) {
				// Retained long enough to investigate abuse, then removed:
				// keeping them forever is a liability, not an asset.
				tag, err := w.app.DB.Exec(ctx,
					`DELETE FROM login_attempts WHERE attempted_at < now() - INTERVAL '90 days'`)
				if err != nil || tag.RowsAffected() == 0 {
					return "", err
				}
				return fmt.Sprintf("removed=%d", tag.RowsAffected()), nil
			},
		},
		{
			Name: "sweep_expired_sessions", Every: time.Hour, Jitter: 5 * time.Minute,
			Run: func(ctx context.Context) (string, error) {
				tag, err := w.app.DB.Exec(ctx,
					`DELETE FROM sessions WHERE absolute_expiry < now() - INTERVAL '7 days'`)
				if err != nil || tag.RowsAffected() == 0 {
					return "", err
				}
				return fmt.Sprintf("removed=%d", tag.RowsAffected()), nil
			},
		},
	}
}

func (w *Worker) expireStaleOrders(ctx context.Context) (string, error) {
	var expired int
	err := w.app.DB.InTx(ctx, db.TxOptions{Name: "expire_orders"}, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, status FROM orders
			 WHERE status IN ('draft','awaiting_payment')
			   AND expires_at IS NOT NULL AND expires_at < now()
			 ORDER BY expires_at LIMIT 200 FOR UPDATE SKIP LOCKED`)
		if err != nil {
			return err
		}
		type row struct {
			id     ids.UUID
			status string
		}
		var batch []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.status); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range batch {
			if _, err := tx.Exec(ctx, `UPDATE orders SET status = 'expired' WHERE id = $1`, r.id); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO order_events (order_id, from_status, to_status, actor_kind, reason)
				VALUES ($1,$2,'expired','system','payment window elapsed')`, r.id, r.status); err != nil {
				return err
			}
			expired++
		}
		return nil
	})
	if err != nil || expired == 0 {
		return "", err
	}
	return fmt.Sprintf("expired=%d", expired), nil
}

// grievanceSLAWatch surfaces breaches of the statutory clocks: acknowledge
// within 24 hours, resolve within 15 days.
func (w *Worker) grievanceSLAWatch(ctx context.Context) (string, error) {
	var ackBreached, resolutionBreached int
	if err := w.app.DB.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE ack_breached),
		       count(*) FILTER (WHERE resolution_breached)
		  FROM grievance_sla_breaches`).Scan(&ackBreached, &resolutionBreached); err != nil {
		return "", fmt.Errorf("worker: grievance sla: %w", err)
	}
	if ackBreached == 0 && resolutionBreached == 0 {
		return "", nil
	}
	// Logged at error level on purpose: these are statutory deadlines under the
	// Consumer Protection (E-Commerce) Rules and the IT Rules, and a missed one
	// should be as loud as a failing payment.
	w.log.ErrorContext(ctx, "grievance SLA breached",
		slog.Int("acknowledgement_overdue", ackBreached),
		slog.Int("resolution_overdue", resolutionBreached))
	return fmt.Sprintf("ack_overdue=%d resolution_overdue=%d", ackBreached, resolutionBreached), nil
}

func (w *Worker) sendQueuedMail(ctx context.Context) (string, error) {
	if w.mailer == nil {
		return "", nil
	}
	sent, failed, err := w.mailer.Drain(ctx, w.app.DB, 50)
	if err != nil || (sent == 0 && failed == 0) {
		return "", err
	}
	return fmt.Sprintf("sent=%d failed=%d", sent, failed), nil
}

// RunOnce executes every scheduled task a single time. Tests use it to drive
// the schedule deterministically instead of waiting on wall-clock timers.
func (w *Worker) RunOnce(ctx context.Context) map[string]error {
	out := map[string]error{}
	for _, task := range w.Tasks() {
		_, err := task.Run(ctx)
		if err != nil {
			out[task.Name] = err
		}
	}
	return out
}

// Run starts the dispatcher and every scheduled task, returning when the
// context is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	w.log.Info("worker starting",
		slog.Int("tasks", len(w.Tasks())),
		slog.Duration("outbox_poll", w.app.Config.Worker.OutboxPollInterval))

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := w.dispatcher.Run(ctx, w.app.Config.Worker.OutboxPollInterval); err != nil &&
			!errors.Is(err, context.Canceled) {
			w.log.Error("outbox dispatcher stopped", slog.String("error", err.Error()))
		}
	}()

	for _, task := range w.Tasks() {
		go w.runTask(ctx, task)
	}

	<-ctx.Done()
	<-done
	w.log.Info("worker stopped")
	return nil
}

func (w *Worker) runTask(ctx context.Context, task Task) {
	// Stagger the first run so a fleet restarting together does not stampede.
	if task.Jitter > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitterFor(w.id+task.Name, task.Jitter)):
		}
	}
	ticker := time.NewTicker(task.Every)
	defer ticker.Stop()

	for {
		start := time.Now()
		note, err := task.Run(ctx)
		elapsed := time.Since(start)

		switch {
		case errors.Is(err, context.Canceled):
			return
		case err != nil:
			w.log.ErrorContext(ctx, "scheduled task failed",
				slog.String("task", task.Name), slog.String("error", err.Error()),
				slog.Float64("duration_ms", float64(elapsed.Microseconds())/1000))
			if w.app.Metrics != nil {
				w.app.Metrics.JobOutcomes.Inc(task.Name, "error")
			}
		default:
			// A task that fires every fifteen seconds and has nothing to report
			// stays silent; otherwise the log is unreadable.
			if note != "" {
				w.log.InfoContext(ctx, "scheduled task", slog.String("task", task.Name),
					slog.String("result", note),
					slog.Float64("duration_ms", float64(elapsed.Microseconds())/1000))
			}
			if w.app.Metrics != nil {
				w.app.Metrics.JobOutcomes.Inc(task.Name, "ok")
			}
		}
		if w.app.Metrics != nil {
			w.app.Metrics.JobDuration.Observe(elapsed.Seconds(), task.Name)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// jitterFor derives a stable offset from the worker identity, so a given
// replica always starts a task at the same point in its window.
func jitterFor(key string, max time.Duration) time.Duration {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(key); i++ {
		h ^= uint64(key[i])
		h *= 1099511628211
	}
	if max <= 0 {
		return 0
	}
	return time.Duration(h % uint64(max))
}
