package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
)

// The job runner drains the `jobs` table.
//
// It is distinct from the outbox dispatcher, and the distinction is worth
// keeping straight. The outbox carries *announcements* — things that happened,
// which the world needs to be told about, delivered at least once and consumed
// idempotently. Jobs are *work* — things that still need doing, which may be
// slow, may fail, and must be retried with backoff until they succeed or are
// given up on.
//
// Scanning a 2 GiB upload is work, not an announcement. Putting it on the
// outbox would block announcement delivery behind it for minutes at a time.

// JobHandler does one unit of work. The payload is the job's JSON.
type JobHandler func(ctx context.Context, payload json.RawMessage) error

// jobHandlers maps a job kind to what performs it.
//
// A job whose kind has no handler is left alone rather than failed: an old
// binary that does not know about a new kind must not consume and discard work
// a newer one would have done. Rolling deploys make that a real case, not a
// hypothetical.
func (w *Worker) jobHandlers() map[string]JobHandler {
	return map[string]JobHandler{
		"scan_asset":           w.jobScanAsset,
		"notify_payout_change": w.jobNotifyPayoutChange,
	}
}

// claimedJob is one row taken off the queue.
type claimedJob struct {
	ID       ids.UUID
	Kind     string
	Payload  json.RawMessage
	Attempts int
	MaxTries int
}

// runJobs claims a batch and runs it.
//
// Claiming uses FOR UPDATE SKIP LOCKED, so N workers never collide and a slow
// job never blocks the queue behind it — the same primitive the outbox uses,
// for the same reason.
func (w *Worker) runJobs(ctx context.Context) (string, error) {
	handlers := w.jobHandlers()
	kinds := make([]string, 0, len(handlers))
	for k := range handlers {
		kinds = append(kinds, k)
	}

	jobs, err := w.claimJobs(ctx, kinds, w.app.Config.Worker.OutboxBatchSize)
	if err != nil {
		return "", err
	}
	if len(jobs) == 0 {
		return "", nil
	}

	var done, failed int
	for _, j := range jobs {
		handler := handlers[j.Kind]
		// Each job gets its own bounded context: one job that hangs must not
		// hold the batch, and a job still running when the process stops is
		// left claimed and reclaimed after its lock expires.
		jobCtx, cancel := context.WithTimeout(ctx, jobTimeout)
		err := handler(jobCtx, j.Payload)
		cancel()

		if err != nil {
			failed++
			w.failJob(ctx, j, err)
			continue
		}
		done++
		w.completeJob(ctx, j)
	}
	return fmt.Sprintf("%d completed, %d failed", done, failed), nil
}

// jobTimeout bounds one job. Generous, because scanning a large upload is the
// slowest thing here and a scan that is merely slow must not be killed and
// retried forever.
const jobTimeout = 20 * time.Minute

func (w *Worker) claimJobs(ctx context.Context, kinds []string, batch int) ([]claimedJob, error) {
	if batch <= 0 {
		batch = 10
	}
	rows, err := w.app.DB.Query(ctx, `
		UPDATE jobs SET locked_at = now(), locked_by = $1, attempts = attempts + 1
		 WHERE id IN (
			SELECT id FROM jobs
			 WHERE completed_at IS NULL AND failed_at IS NULL
			   AND run_at <= now()
			   AND kind = ANY($2)
			   AND (locked_at IS NULL OR locked_at < now() - INTERVAL '30 minutes')
			 ORDER BY priority, run_at, id
			 FOR UPDATE SKIP LOCKED
			 LIMIT $3
		 )
		 RETURNING id, kind, payload, attempts, max_attempts`,
		w.id, kinds, batch)
	if err != nil {
		return nil, fmt.Errorf("worker: claiming jobs: %w", err)
	}
	defer rows.Close()

	var out []claimedJob
	for rows.Next() {
		var j claimedJob
		if err := rows.Scan(&j.ID, &j.Kind, &j.Payload, &j.Attempts, &j.MaxTries); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (w *Worker) completeJob(ctx context.Context, j claimedJob) {
	if _, err := w.app.DB.Exec(ctx,
		`UPDATE jobs SET completed_at = now(), locked_at = NULL, locked_by = NULL WHERE id = $1`,
		j.ID); err != nil {
		w.log.Error("marking a job complete", slog.String("job", j.ID.String()),
			slog.String("kind", j.Kind), slog.String("error", err.Error()))
	}
}

// failJob records the error and schedules a retry, or gives up.
//
// Giving up is deliberately loud and deliberately terminal: a job that has
// failed its full allowance is a bug or an outage, and quietly retrying it
// forever would hide both while consuming the queue.
func (w *Worker) failJob(ctx context.Context, j claimedJob, cause error) {
	level := slog.LevelWarn
	if j.Attempts >= j.MaxTries {
		level = slog.LevelError
	}
	w.log.Log(ctx, level, "job failed",
		slog.String("job", j.ID.String()), slog.String("kind", j.Kind),
		slog.Int("attempt", j.Attempts), slog.Int("max_attempts", j.MaxTries),
		slog.String("error", cause.Error()))

	if j.Attempts >= j.MaxTries {
		if _, err := w.app.DB.Exec(ctx,
			`UPDATE jobs SET failed_at = now(), last_error = $2, locked_at = NULL, locked_by = NULL WHERE id = $1`,
			j.ID, cause.Error()); err != nil {
			w.log.Error("marking a job failed", slog.String("error", err.Error()))
		}
		return
	}

	if _, err := w.app.DB.Exec(ctx, `
		UPDATE jobs SET run_at = now() + $2::interval, last_error = $3,
		       locked_at = NULL, locked_by = NULL
		 WHERE id = $1`,
		j.ID, jobBackoff(j.Attempts).String(), cause.Error()); err != nil {
		w.log.Error("rescheduling a job", slog.String("error", err.Error()))
	}
}

// jobBackoff grows exponentially and caps, so a persistent failure backs off to
// a slow retry rather than either hammering or giving up immediately.
func jobBackoff(attempt int) time.Duration {
	d := time.Duration(1<<min(attempt, 10)) * time.Second
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	return d
}

// ---- handlers ---------------------------------------------------------------

func (w *Worker) jobScanAsset(ctx context.Context, payload json.RawMessage) error {
	var p struct {
		AssetPublicID string `json:"asset_public_id"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("worker: malformed scan_asset payload: %w", err)
	}
	if p.AssetPublicID == "" {
		return fmt.Errorf("worker: scan_asset payload names no asset")
	}
	if w.app.Catalog == nil {
		return fmt.Errorf("worker: no catalogue service is configured")
	}
	return w.app.Catalog.ScanAsset(ctx, p.AssetPublicID)
}

// jobNotifyPayoutChange warns a seller that their payout destination changed.
//
// This is the control that makes the 48-hour quarantine mean something: the
// window only protects a seller who is told there is something to object to.
func (w *Worker) jobNotifyPayoutChange(ctx context.Context, payload json.RawMessage) error {
	var p struct {
		SellerID   string `json:"seller_id"`
		Last4      string `json:"last4"`
		ActiveFrom string `json:"active_from"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("worker: malformed notify_payout_change payload: %w", err)
	}

	sellerID, err := ids.ParseUUID(p.SellerID)
	if err != nil {
		return fmt.Errorf("worker: malformed seller id in notify_payout_change: %w", err)
	}

	return w.app.DB.InTx(ctx, db.TxOptions{Name: "notify_payout_change"}, func(ctx context.Context, tx db.Tx) error {
		var userID ids.UUID
		var handle string
		if err := tx.QueryRow(ctx,
			`SELECT user_id, handle FROM sellers WHERE id = $1`, sellerID).Scan(&userID, &handle); err != nil {
			return fmt.Errorf("worker: seller %s not found: %w", p.SellerID, err)
		}
		vars, err := json.Marshal(map[string]any{
			"handle": handle, "last4": p.Last4, "active_from": p.ActiveFrom,
		})
		if err != nil {
			return err
		}
		// Transactional, which in the consent model means mandatory rather than
		// consent-gated. That is the correct category for this: a warning a
		// seller could unsubscribe from would not be a control.
		_, err = tx.Exec(ctx, `
			INSERT INTO notifications (id, public_id, user_id, channel, template, variables, category)
			VALUES ($1, $2, $3, 'email', 'payout_destination_changed', $4::jsonb, 'transactional')
			ON CONFLICT DO NOTHING`,
			ids.NewUUIDv7(), ids.NewPublic(ids.PrefixNotification), userID, vars)
		return err
	})
}
