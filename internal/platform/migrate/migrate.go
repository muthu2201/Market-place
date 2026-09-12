// Package migrate applies embedded SQL migrations exactly once, in order, under
// an advisory lock, and verifies that already-applied files have not been
// edited.
//
// Editing an applied migration is the single most common way a team ends up
// with environments that differ in ways nobody can see. The checksum turns that
// into a loud boot failure instead of a silent divergence.
package migrate

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	migrations "github.com/muthu2201/market-place/db/migrations"
)

// advisoryLockKey is an arbitrary but fixed 64-bit value. Two concurrently
// starting replicas therefore serialise rather than race to apply the same file.
const advisoryLockKey int64 = 0x4D41524B4554504C // "MARKETPL"

// Migration is one file.
type Migration struct {
	Version  string
	Name     string
	SQL      string
	Checksum [32]byte
}

// Load reads and sorts migrations from an embedded filesystem.
func Load(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("migrate: read %s: %w", dir, err)
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("migrate: read %s: %w", e.Name(), err)
		}
		version, name, ok := strings.Cut(strings.TrimSuffix(e.Name(), ".sql"), "_")
		if !ok {
			return nil, fmt.Errorf("migrate: %q must be named <version>_<name>.sql", e.Name())
		}
		out = append(out, Migration{
			Version:  version,
			Name:     name,
			SQL:      string(body),
			Checksum: sha256.Sum256(body),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })

	seen := make(map[string]struct{}, len(out))
	for _, m := range out {
		if _, dup := seen[m.Version]; dup {
			return nil, fmt.Errorf("migrate: duplicate version %s", m.Version)
		}
		seen[m.Version] = struct{}{}
	}
	return out, nil
}

// Result describes what one run did.
type Result struct {
	Applied []string
	Skipped []string
}

// ErrDrift means an already-applied migration file has since been edited.
var ErrDrift = errors.New("migrate: an applied migration has been modified")

// Up applies every pending migration. Each file runs inside its own
// transaction, so a failure leaves the database at a known version.
func Up(ctx context.Context, pool *pgxpool.Pool, migrations []Migration) (Result, error) {
	var res Result

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return res, fmt.Errorf("migrate: acquire: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		return res, fmt.Errorf("migrate: advisory lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, advisoryLockKey)
	}()

	if err := ensureTable(ctx, conn.Conn()); err != nil {
		return res, err
	}

	applied, err := loadApplied(ctx, conn.Conn())
	if err != nil {
		return res, err
	}

	for _, m := range migrations {
		if have, ok := applied[m.Version]; ok {
			if have != m.Checksum {
				return res, fmt.Errorf("%w: %s_%s (recorded %x, file %x)",
					ErrDrift, m.Version, m.Name, have[:8], m.Checksum[:8])
			}
			res.Skipped = append(res.Skipped, m.Version)
			continue
		}
		start := time.Now()
		if err := applyOne(ctx, conn.Conn(), m, start); err != nil {
			return res, err
		}
		res.Applied = append(res.Applied, m.Version+"_"+m.Name)
	}
	return res, nil
}

func ensureTable(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
		  version     TEXT PRIMARY KEY,
		  checksum    BYTEA NOT NULL,
		  applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
		  duration_ms INTEGER NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("migrate: ensure schema_migrations: %w", err)
	}
	return nil
}

func loadApplied(ctx context.Context, conn *pgx.Conn) (map[string][32]byte, error) {
	rows, err := conn.Query(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("migrate: read schema_migrations: %w", err)
	}
	defer rows.Close()

	out := make(map[string][32]byte)
	for rows.Next() {
		var v string
		var sum []byte
		if err := rows.Scan(&v, &sum); err != nil {
			return nil, fmt.Errorf("migrate: scan schema_migrations: %w", err)
		}
		var fixed [32]byte
		copy(fixed[:], sum)
		out[v] = fixed
	}
	return out, rows.Err()
}

func applyOne(ctx context.Context, conn *pgx.Conn, m Migration, start time.Time) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("migrate: begin %s: %w", m.Version, err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		return fmt.Errorf("migrate: apply %s_%s: %w", m.Version, m.Name, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version, checksum, duration_ms) VALUES ($1, $2, $3)`,
		m.Version, m.Checksum[:], int(time.Since(start).Milliseconds()),
	); err != nil {
		return fmt.Errorf("migrate: record %s: %w", m.Version, err)
	}
	return tx.Commit(ctx)
}

// Status reports the applied and pending sets without changing anything.
func Status(ctx context.Context, pool *pgxpool.Pool, migrations []Migration) (appliedVersions, pending []string, err error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Release()
	if err := ensureTable(ctx, conn.Conn()); err != nil {
		return nil, nil, err
	}
	applied, err := loadApplied(ctx, conn.Conn())
	if err != nil {
		return nil, nil, err
	}
	for _, m := range migrations {
		if _, ok := applied[m.Version]; ok {
			appliedVersions = append(appliedVersions, m.Version+"_"+m.Name)
		} else {
			pending = append(pending, m.Version+"_"+m.Name)
		}
	}
	return appliedVersions, pending, nil
}

// Embedded returns the migrations compiled into the binary.
func Embedded() ([]Migration, error) { return Load(migrations.Files, ".") }
