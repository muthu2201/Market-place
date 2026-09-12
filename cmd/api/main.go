// Command api runs the HTTP server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/muthu2201/market-place/internal/app"
	"github.com/muthu2201/market-place/internal/platform/config"
)

// healthcheck makes the binary able to probe itself.
//
// The runtime image is distroless: no shell, no curl, nothing to write a probe
// with. Container healthchecks and Kubernetes exec probes therefore need the
// binary to be able to check itself, and the alternative — adding a shell to
// the image — would give an attacker who achieves code execution something to
// pivot with, which is exactly what distroless exists to remove.
var healthcheck = flag.Bool("healthcheck", false,
	"probe this instance's own liveness endpoint, then exit 0 if healthy and 1 if not")

func main() {
	flag.Parse()

	if *healthcheck {
		if err := probeSelf(); err != nil {
			fmt.Fprintln(os.Stderr, "api: healthcheck:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "api:", err)
		os.Exit(1)
	}
}

// probeSelf requests /healthz from the address this process would listen on.
//
// Liveness, deliberately, not readiness: a database blip must not make an
// orchestrator kill healthy replicas and turn a degradation into an outage.
// Readiness is /readyz, which the load balancer polls over the network.
func probeSelf() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// A listen address of 0.0.0.0 or :: is not connectable; probe loopback.
	host, port, err := net.SplitHostPort(cfg.HTTP.Addr)
	if err != nil {
		return fmt.Errorf("unusable listen address %q: %w", cfg.HTTP.Addr, err)
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("/healthz returned %s", resp.Status)
	}
	return nil
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

	// Shutdown in two phases.
	//
	// First: report not-ready while still serving. A load balancer keeps
	// sending to this instance for a second or two after the pod is deleted,
	// and if the process stopped accepting immediately those requests would
	// fail. Waiting here costs a few seconds of a deploy and removes a class
	// of user-visible error that is otherwise very hard to explain.
	if cfg.HTTP.DrainDelay > 0 {
		application.Server.BeginDraining()
		application.Log.Info("draining: reporting not-ready while still serving",
			slog.Duration("delay", cfg.HTTP.DrainDelay))
		drainTimer := time.NewTimer(cfg.HTTP.DrainDelay)
		<-drainTimer.C
	}

	// Second: stop accepting, let in-flight requests finish. A checkout that is
	// mid-capture must not be cut off by a deploy.
	application.Log.Info("shutting down", slog.Duration("grace", cfg.HTTP.ShutdownGrace))
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}
	application.Log.Info("stopped cleanly")
	return nil
}
