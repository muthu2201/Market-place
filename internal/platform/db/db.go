// Package db owns the PostgreSQL connection pool and the transaction contract.
//
// Three rules are enforced here and nowhere else:
//
//  1. Every statement carries a timeout. A query with no deadline is how a
//     single slow plan takes down a whole pool.
//  2. Write transactions run at REPEATABLE READ or SERIALIZABLE and are retried
//     on 40001/40P01. Callers therefore must supply idempotent closures.
//  3. Only parameterised queries are possible: the DB interface accepts a SQL
//     string plus args and nothing in this package concatenates user input.
package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/metrics"
)

// Querier is the read/write surface shared by the pool and by a transaction, so
// repository code compiles identically inside or outside a transaction.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	CopyFrom(ctx context.Context, table pgx.Identifier, cols []string, src pgx.CopyFromSource) (int64, error)
}

// Tx is a Querier that is statically known to be inside an explicit
// transaction. Operations whose correctness depends on atomicity (posting a
// journal entry with its lines, claiming an idempotency key alongside the work
// it guards) take a Tx rather than a Querier, so calling them on a bare pool is
// a compile error rather than a runtime surprise.
type Tx interface {
	Querier
	// inTransaction is unexported so only this package can implement Tx.
	inTransaction()
}

// DB wraps the pool with instrumentation and the transaction helpers.
type DB struct {
	pool     *pgxpool.Pool
	m        *metrics.App
	stmtTO   time.Duration
	maxRetry int
}

var _ Querier = (*DB)(nil)

// Open builds a configured, verified pool. It fails rather than returning a
// pool that cannot reach the database, so a boot failure is loud.
func Open(ctx context.Context, cfg config.DatabaseConfig, m *metrics.App) (*DB, error) {
	pc, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("db: parse DATABASE_URL: %w", err)
	}
	pc.MaxConns = cfg.MaxConns
	pc.MinConns = cfg.MinConns
	pc.MaxConnLifetime = cfg.MaxConnLifetime
	pc.MaxConnIdleTime = cfg.MaxConnIdleTime
	pc.ConnConfig.ConnectTimeout = cfg.ConnectTimeout

	// A server-side statement timeout is the backstop for any context deadline
	// that a caller forgets. idle_in_transaction_session_timeout stops a leaked
	// transaction from pinning rows and blocking vacuum indefinitely.
	if pc.ConnConfig.RuntimeParams == nil {
		pc.ConnConfig.RuntimeParams = map[string]string{}
	}
	pc.ConnConfig.RuntimeParams["statement_timeout"] = fmt.Sprint(cfg.StatementTimeout.Milliseconds())
	pc.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = fmt.Sprint((30 * time.Second).Milliseconds())
	pc.ConnConfig.RuntimeParams["application_name"] = "marketplace"
	// Belt and braces against SQL injection via a second statement: pgx uses the
	// extended protocol by default, which does not permit multiple statements.
	pc.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement

	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("db: create pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return &DB{pool: pool, m: m, stmtTO: cfg.StatementTimeout, maxRetry: 5}, nil
}

func (d *DB) Pool() *pgxpool.Pool { return d.pool }

func (d *DB) Close() { d.pool.Close() }

// Ping is used by the readiness probe.
func (d *DB) Ping(ctx context.Context) error { return d.pool.Ping(ctx) }

// ReportPoolStats publishes pool occupancy; the worker calls it on a ticker.
func (d *DB) ReportPoolStats() {
	if d.m == nil {
		return
	}
	s := d.pool.Stat()
	d.m.DBPoolConns.Set(float64(s.AcquiredConns()), "acquired")
	d.m.DBPoolConns.Set(float64(s.IdleConns()), "idle")
	d.m.DBPoolConns.Set(float64(s.TotalConns()), "total")
	d.m.DBPoolConns.Set(float64(s.MaxConns()), "max")
}

func (d *DB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	defer d.observe(time.Now(), opName(sql))
	return d.pool.Exec(ctx, sql, args...)
}

func (d *DB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	defer d.observe(time.Now(), opName(sql))
	return d.pool.Query(ctx, sql, args...)
}

func (d *DB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	defer d.observe(time.Now(), opName(sql))
	return d.pool.QueryRow(ctx, sql, args...)
}

func (d *DB) CopyFrom(ctx context.Context, table pgx.Identifier, cols []string, src pgx.CopyFromSource) (int64, error) {
	defer d.observe(time.Now(), "copy_from")
	return d.pool.CopyFrom(ctx, table, cols, src)
}

func (d *DB) observe(start time.Time, op string) {
	if d.m != nil {
		d.m.DBQueryDuration.Observe(time.Since(start).Seconds(), op)
	}
}

// TxOptions selects the isolation level for a unit of work.
type TxOptions struct {
	// Name labels the transaction in metrics and logs.
	Name string
	// Isolation defaults to RepeatableRead. Use Serializable for anything that
	// reads a set of rows and then writes a value derived from that set
	// (balance checks, exposure caps, quota enforcement).
	Isolation pgx.TxIsoLevel
	// ReadOnly lets Postgres skip work and protects against accidental writes
	// in a reporting path.
	ReadOnly bool
}

// ErrRollback can be returned from a transaction closure to roll back without
// surfacing an error to the caller.
var ErrRollback = errors.New("db: rollback requested")

// InTx runs fn inside a transaction, retrying serialization failures and
// deadlocks with exponential backoff and full jitter.
//
// fn MUST be idempotent: it can be executed more than once.
func (d *DB) InTx(ctx context.Context, o TxOptions, fn func(ctx context.Context, tx Tx) error) error {
	if o.Isolation == "" {
		o.Isolation = pgx.RepeatableRead
	}
	if o.Name == "" {
		o.Name = "tx"
	}
	access := pgx.ReadWrite
	if o.ReadOnly {
		access = pgx.ReadOnly
	}

	var lastErr error
	backoff := 5 * time.Millisecond
	for attempt := 0; attempt <= d.maxRetry; attempt++ {
		if attempt > 0 {
			if d.m != nil {
				d.m.DBTxRetries.Inc(o.Name)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(jitter(backoff)):
			}
			backoff *= 2
			if backoff > 500*time.Millisecond {
				backoff = 500 * time.Millisecond
			}
		}

		err := d.runOnce(ctx, o, access, fn)
		if err == nil {
			return nil
		}
		if errors.Is(err, ErrRollback) {
			return nil
		}
		if !isRetryable(err) {
			return err
		}
		lastErr = err
	}
	return fmt.Errorf("db: %s exhausted %d retries: %w", o.Name, d.maxRetry, lastErr)
}

func (d *DB) runOnce(ctx context.Context, o TxOptions, access pgx.TxAccessMode, fn func(context.Context, Tx) error) (err error) {
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: o.Isolation, AccessMode: access})
	if err != nil {
		return fmt.Errorf("db: begin %s: %w", o.Name, err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()

	start := time.Now()
	if err = fn(ctx, txQuerier{tx}); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("db: commit %s: %w", o.Name, err)
	}
	if d.m != nil {
		d.m.DBQueryDuration.Observe(time.Since(start).Seconds(), o.Name)
	}
	return nil
}

type txQuerier struct{ tx pgx.Tx }

var _ Tx = txQuerier{}

func (txQuerier) inTransaction() {}

func (t txQuerier) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return t.tx.Exec(ctx, sql, args...)
}
func (t txQuerier) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return t.tx.Query(ctx, sql, args...)
}
func (t txQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return t.tx.QueryRow(ctx, sql, args...)
}
func (t txQuerier) CopyFrom(ctx context.Context, table pgx.Identifier, cols []string, src pgx.CopyFromSource) (int64, error) {
	return t.tx.CopyFrom(ctx, table, cols, src)
}

// idempotencyConstraints are unique indexes that represent an "I claim this
// key" race rather than a data error.
//
// Under REPEATABLE READ a concurrent transaction that commits after our
// snapshot is invisible to us, so our own INSERT surfaces as 23505 rather than
// as 40001. Retrying the whole unit of work takes a fresh snapshot, at which
// point the winner's row is visible and the loser takes the replay path. Every
// unit of work guarded by one of these keys is idempotent by construction,
// which is exactly what makes the retry safe.
var idempotencyConstraints = map[string]bool{
	"journal_entries_idempotency_uq": true,
	"idempotency_keys_unique_idx":    true,
	"provider_webhook_events_uq":     true,
	"jobs_unique_key_idx":            true,
}

// isRetryable reports whether an error is a transient concurrency conflict.
func isRetryable(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "40001", // serialization_failure
			"40P01": // deadlock_detected
			return true
		case "23505": // unique_violation
			return idempotencyConstraints[pgErr.ConstraintName]
		}
	}
	return false
}

// IsUniqueViolation reports a 23505, which repositories translate into a domain
// conflict rather than a 500.
func IsUniqueViolation(err error) (constraint string, ok bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return pgErr.ConstraintName, true
	}
	return "", false
}

// IsForeignKeyViolation reports a 23503.
func IsForeignKeyViolation(err error) (constraint string, ok bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return pgErr.ConstraintName, true
	}
	return "", false
}

// IsCheckViolation reports a 23514, which is how the ledger's balance rule and
// the state-machine guards surface.
func IsCheckViolation(err error) (constraint string, ok bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23514" {
		return pgErr.ConstraintName, true
	}
	return "", false
}

// IsRaisedException reports a P0001 raised by a trigger, carrying its message.
func IsRaisedException(err error) (message string, ok bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "P0001" {
		return pgErr.Message, true
	}
	return "", false
}

// IsNoRows is a readable wrapper over pgx.ErrNoRows.
func IsNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// opName derives a low-cardinality metric label from a statement.
func opName(sql string) string {
	s := strings.TrimSpace(sql)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 48 {
		s = s[:48]
	}
	f := strings.Fields(s)
	if len(f) == 0 {
		return "unknown"
	}
	verb := strings.ToLower(f[0])
	switch verb {
	case "select", "insert", "update", "delete", "with":
		if len(f) > 2 {
			return verb + "_" + sanitiseIdent(f[len(f)-1])
		}
		return verb
	}
	return verb
}

func sanitiseIdent(s string) string {
	s = strings.Trim(s, "(),;\"")
	if len(s) > 24 {
		s = s[:24]
	}
	for _, r := range s {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return "expr"
		}
	}
	if s == "" {
		return "expr"
	}
	return strings.ToLower(s)
}

var jitterSeed uint64 = 0x2545F4914F6CDD1D

func jitter(d time.Duration) time.Duration {
	// xorshift: deterministic enough for backoff, no crypto/rand cost on a hot path.
	jitterSeed ^= jitterSeed << 13
	jitterSeed ^= jitterSeed >> 7
	jitterSeed ^= jitterSeed << 17
	if d <= 0 {
		return 0
	}
	return time.Duration(jitterSeed % uint64(d))
}
