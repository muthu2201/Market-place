// Package dbtest gives integration tests a real PostgreSQL database.
//
// There is no in-memory substitute here on purpose. Half of this system's
// correctness lives in constraints, triggers and deferred checks, so a test
// that does not run against PostgreSQL would be testing a different program.
package dbtest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/metrics"
	"github.com/muthu2201/market-place/internal/platform/migrate"
)

const defaultURL = "postgres://marketplace:dev_local_only_pw@127.0.0.1:5432/marketplace_test?sslmode=disable"

// templateSuffix names the database that is migrated once and then cloned.
// Cloning a template is a file copy inside PostgreSQL, so each test binary gets
// a private, fully-migrated database in milliseconds.
const templateSuffix = "_template"

var (
	once         sync.Once
	shared       *db.DB
	effectiveDSN string
	initErr      error
	registry     = metrics.NewRegistry()
	appMetrics   *metrics.App
)

// EffectiveURL returns the DSN of the database private to this test binary.
//
// Tests that build the application must pass this, not URL(): pointing the
// application at the shared base database while the harness truncates the
// private clone is a state leak that produces failures with no obvious cause.
func EffectiveURL(t *testing.T) string {
	t.Helper()
	Open(t)
	return effectiveDSN
}

// URL returns the base test database DSN, honouring TEST_DATABASE_URL.
func URL() string {
	if v := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")); v != "" {
		return v
	}
	return defaultURL
}

// Open returns a pool against a database private to THIS test binary.
//
// Sharing one database across packages is what made `go test ./...` deadlock:
// package A's TRUNCATE collided with package B's in-flight work. Each binary
// now clones a pre-migrated template instead, so packages are isolated and the
// suite runs in parallel at full speed.
//
// It skips rather than fails when no database is reachable, so `go test ./...`
// still works on a machine without PostgreSQL while CI runs the full suite.
func Open(t *testing.T) *db.DB {
	t.Helper()
	once.Do(func() {
		appMetrics = metrics.NewApp(registry)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		base, err := url.Parse(URL())
		if err != nil {
			initErr = err
			return
		}
		baseName := strings.TrimPrefix(base.Path, "/")
		templateName := baseName + templateSuffix
		privateName := baseName + "_" + binaryTag()

		if err := ensureTemplate(ctx, base, templateName); err != nil {
			initErr = err
			return
		}
		if err := cloneDatabase(ctx, base, templateName, privateName); err != nil {
			initErr = err
			return
		}

		private := *base
		private.Path = "/" + privateName
		effectiveDSN = private.String()
		d, err := db.Open(ctx, config.DatabaseConfig{
			URL: effectiveDSN, MaxConns: 16, MinConns: 1,
			MaxConnLifetime: time.Hour, MaxConnIdleTime: 10 * time.Minute,
			StatementTimeout: 30 * time.Second, ConnectTimeout: 5 * time.Second,
		}, appMetrics)
		if err != nil {
			initErr = err
			return
		}
		shared = d
	})
	if initErr != nil {
		t.Skipf("integration test skipped: no test database available (%v)", initErr)
	}
	return shared
}

// binaryTag derives a stable, filesystem-safe name from the test binary, so a
// package always lands on the same database and leftovers do not accumulate.
func binaryTag() string {
	name := filepath.Base(os.Args[0])
	name = strings.TrimSuffix(name, ".test")
	sum := sha256.Sum256([]byte(os.Args[0]))
	safe := make([]byte, 0, len(name))
	for i := 0; i < len(name) && i < 24; i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			safe = append(safe, c)
		} else if c >= 'A' && c <= 'Z' {
			safe = append(safe, c+32)
		} else {
			safe = append(safe, '_')
		}
	}
	return string(safe) + "_" + hex.EncodeToString(sum[:4])
}

// maintenanceConn opens a connection to the "postgres" database, which is where
// CREATE DATABASE and DROP DATABASE must be issued from.
func maintenanceConn(ctx context.Context, base *url.URL) (*pgx.Conn, error) {
	admin := *base
	admin.Path = "/postgres"
	return pgx.Connect(ctx, admin.String())
}

// ensureTemplate migrates the template database once, under an advisory lock so
// several test binaries starting together do not race.
func ensureTemplate(ctx context.Context, base *url.URL, templateName string) error {
	admin, err := maintenanceConn(ctx, base)
	if err != nil {
		return fmt.Errorf("connect to maintenance database: %w", err)
	}
	defer admin.Close(context.WithoutCancel(ctx))

	if _, err := admin.Exec(ctx, `SELECT pg_advisory_lock($1)`, int64(0x7E5700000001)); err != nil {
		return fmt.Errorf("template lock: %w", err)
	}
	defer func() {
		_, _ = admin.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, int64(0x7E5700000001))
	}()

	var exists bool
	if err := admin.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, templateName).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE "`+templateName+`"`); err != nil {
			return fmt.Errorf("create template: %w", err)
		}
	}

	tmpl := *base
	tmpl.Path = "/" + templateName
	pool, err := pgxpool.New(ctx, tmpl.String())
	if err != nil {
		return fmt.Errorf("connect template: %w", err)
	}
	defer pool.Close()

	for _, ext := range []string{"pg_trgm", "pgcrypto", "btree_gist"} {
		if _, err := pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS `+ext); err != nil {
			return fmt.Errorf("create extension %s: %w", ext, err)
		}
	}
	migrations, err := migrate.Embedded()
	if err != nil {
		return err
	}
	if _, err := migrate.Up(ctx, pool, migrations); err != nil {
		return fmt.Errorf("migrate template: %w", err)
	}
	return nil
}

// cloneDatabase drops any previous copy and clones the template.
func cloneDatabase(ctx context.Context, base *url.URL, templateName, target string) error {
	admin, err := maintenanceConn(ctx, base)
	if err != nil {
		return err
	}
	defer admin.Close(context.WithoutCancel(ctx))

	// Any connection to the template blocks CREATE DATABASE ... TEMPLATE, and
	// any connection to the target blocks the drop.
	for _, name := range []string{target} {
		if _, err := admin.Exec(ctx, `
			SELECT pg_terminate_backend(pid) FROM pg_stat_activity
			 WHERE datname = $1 AND pid <> pg_backend_pid()`, name); err != nil {
			return fmt.Errorf("evict connections to %s: %w", name, err)
		}
	}
	if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS "`+target+`"`); err != nil {
		return fmt.Errorf("drop %s: %w", target, err)
	}
	if _, err := admin.Exec(ctx, `
		SELECT pg_terminate_backend(pid) FROM pg_stat_activity
		 WHERE datname = $1 AND pid <> pg_backend_pid()`, templateName); err != nil {
		return fmt.Errorf("evict connections to the template: %w", err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+target+`" TEMPLATE "`+templateName+`"`); err != nil {
		return fmt.Errorf("clone template into %s: %w", target, err)
	}
	return nil
}

// Metrics exposes the registry the test pool reports into.
func Metrics() *metrics.App { return appMetrics }

// tablesToPreserve are reference data seeded by migrations. Truncating them
// would break every subsequent test in the process.
var tablesToPreserve = map[string]bool{
	"schema_migrations":         true,
	"roles":                     true,
	"order_transitions_allowed": true,
	"ledger_accounts":           true,
	"fee_schedules":             true,
}

// Reset truncates every mutable table so each test starts from a known state.
// Triggers that make tables append-only are disabled for the truncate and
// restored immediately afterwards; TRUNCATE does not fire row triggers, but the
// session_replication_role switch also covers the FK graph.
func Reset(t *testing.T, d *db.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rows, err := d.Query(ctx, `
		SELECT tablename FROM pg_tables
		 WHERE schemaname = 'public'
		 ORDER BY tablename`)
	if err != nil {
		t.Fatalf("dbtest: list tables: %v", err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			t.Fatalf("dbtest: scan table name: %v", err)
		}
		if !tablesToPreserve[n] {
			names = append(names, `"`+n+`"`)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("dbtest: list tables: %v", err)
	}
	if len(names) == 0 {
		return
	}
	if _, err := d.Exec(ctx, `TRUNCATE TABLE `+strings.Join(names, ", ")+` RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("dbtest: truncate: %v", err)
	}
	// Seller subsidiary ledger accounts are opened on demand; clear them so
	// account ids do not leak between tests, keeping the seeded platform chart.
	if _, err := d.Exec(ctx, `DELETE FROM ledger_account_balances`); err != nil {
		t.Fatalf("dbtest: clear balances: %v", err)
	}
	if _, err := d.Exec(ctx, `DELETE FROM ledger_accounts WHERE owner_type = 'seller'`); err != nil {
		t.Fatalf("dbtest: clear seller accounts: %v", err)
	}
}

// Fresh opens the pool and resets it, the usual first line of a test.
func Fresh(t *testing.T) *db.DB {
	t.Helper()
	d := Open(t)
	Reset(t, d)
	return d
}

// Ctx returns a context with a sensible per-test deadline.
func Ctx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}
