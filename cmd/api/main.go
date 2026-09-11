// Command api runs the HTTP server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/muthu2201/market-place/internal/app"
	"github.com/muthu2201/market-place/internal/platform/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "api:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bootCtx, cancelBoot := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelBoot()

	application, err := app.Build(bootCtx, cfg, app.Options{})
	if err != nil {
		return err
	}
	defer application.Close()

	go application.SweepLimiter(ctx, time.Minute)

	srv := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           application.Server.Handler(),
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		// Errors from the HTTP server itself go through the structured logger
		// so they are not lost to stderr in a container.
		ErrorLog: slog.NewLogLogger(application.Log.Handler(), slog.LevelWarn),
	}

	errCh := make(chan error, 1)
	go func() {
		application.Log.Info("http server listening",
			slog.String("addr", cfg.HTTP.Addr),
			slog.String("public_url", cfg.HTTP.PublicBaseURL.String()))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	// Graceful shutdown: stop accepting, let in-flight requests finish. A
	// checkout that is mid-capture must not be cut off by a deploy.
	application.Log.Info("shutting down", slog.Duration("grace", cfg.HTTP.ShutdownGrace))
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}
	application.Log.Info("stopped cleanly")
	return nil
}
