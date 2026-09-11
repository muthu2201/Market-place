// Command worker runs the outbox dispatcher and the scheduled tasks.
//
// It is a separate process from the API on purpose: a slow background job must
// not consume the connection pool the request path depends on, and the two
// scale independently.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/muthu2201/market-place/internal/app"
	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/mail"
	"github.com/muthu2201/market-place/internal/worker"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "worker:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if !cfg.Worker.Enabled {
		fmt.Println("worker: disabled by configuration (WORKER_ENABLED=false)")
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bootCtx, cancelBoot := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelBoot()

	// The worker does not run migrations: the API owns the schema, and two
	// processes racing to migrate is a failure mode worth not having.
	application, err := app.Build(bootCtx, cfg, app.Options{SkipMigrations: true})
	if err != nil {
		return err
	}
	defer application.Close()

	renderer, err := mail.NewRenderer("Marketplace",
		cfg.HTTP.PublicBaseURL.String(), cfg.Platform.GrievanceOfficerEmail)
	if err != nil {
		return err
	}

	var transport mail.Transport
	switch cfg.Mail.Driver {
	case "smtp":
		transport = mail.SMTPTransport{
			Host: cfg.Mail.SMTPHost, Port: cfg.Mail.SMTPPort,
			Username: cfg.Mail.SMTPUser, Password: cfg.Mail.SMTPPass,
			From: cfg.Mail.FromAddress, FromName: cfg.Mail.FromName,
			Timeout: cfg.Mail.Timeout,
		}
	default:
		transport = mail.LogTransport{Log: application.Log}
	}
	queue := mail.NewQueue(transport, renderer, application.Identity.Vault(), application.Log, cfg.Mail)

	application.Log.Info("worker configured",
		slog.String("mail_transport", transport.Name()),
		slog.Int("job_concurrency", cfg.Worker.JobConcurrency))

	go application.SweepLimiter(ctx, time.Minute)
	return worker.New(application, queue).Run(ctx)
}
