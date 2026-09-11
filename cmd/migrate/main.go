// Command migrate applies the embedded database migrations.
//
//	migrate up      - apply everything pending
//	migrate status  - show applied and pending without changing anything
//	migrate verify  - fail if any applied migration file has been edited
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muthu2201/market-place/internal/platform/migrate"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		os.Exit(1)
	}
}

func run() error {
	cmd := "up"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	migrations, err := migrate.Embedded()
	if err != nil {
		return err
	}

	switch cmd {
	case "up":
		res, err := migrate.Up(ctx, pool, migrations)
		if err != nil {
			return err
		}
		for _, v := range res.Applied {
			fmt.Println("applied", v)
		}
		fmt.Printf("done: %d applied, %d already present\n", len(res.Applied), len(res.Skipped))
		return nil

	case "status":
		applied, pending, err := migrate.Status(ctx, pool, migrations)
		if err != nil {
			return err
		}
		fmt.Printf("applied (%d):\n", len(applied))
		for _, v := range applied {
			fmt.Println("  ", v)
		}
		fmt.Printf("pending (%d):\n", len(pending))
		for _, v := range pending {
			fmt.Println("  ", v)
		}
		return nil

	case "verify":
		if _, _, err := migrate.Status(ctx, pool, migrations); err != nil {
			return err
		}
		// Up with nothing pending is the cheapest way to run the drift check.
		if _, err := migrate.Up(ctx, pool, migrations); err != nil {
			return err
		}
		fmt.Println("schema verified: no drift")
		return nil

	default:
		return fmt.Errorf("unknown command %q (want up|status|verify)", cmd)
	}
}
