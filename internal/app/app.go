// Package app is the composition root: it builds every service from validated
// configuration and wires them together.
//
// Keeping construction in one place means the full dependency graph of the
// system is readable top to bottom in a single file, and that a service can
// never quietly acquire a dependency the architecture does not permit.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/muthu2201/market-place/internal/api"
	"github.com/muthu2201/market-place/internal/modules/audit"
	"github.com/muthu2201/market-place/internal/modules/delivery"
	"github.com/muthu2201/market-place/internal/modules/identity"
	"github.com/muthu2201/market-place/internal/modules/ledger"
	"github.com/muthu2201/market-place/internal/modules/orders"
	"github.com/muthu2201/market-place/internal/modules/payments"
	"github.com/muthu2201/market-place/internal/modules/tax"
	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/cryptox"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/logx"
	"github.com/muthu2201/market-place/internal/platform/metrics"
	"github.com/muthu2201/market-place/internal/platform/migrate"
	"github.com/muthu2201/market-place/internal/platform/ratelimit"
	"github.com/muthu2201/market-place/internal/storage"
)

// App holds every constructed component.
type App struct {
	Config   *config.Config
	Log      *slog.Logger
	DB       *db.DB
	Metrics  *metrics.App
	Registry *metrics.Registry
	Clock    clock.Clock

	Vault    *identity.Vault
	Identity *identity.Service
	Ledger   *ledger.Service
	Provider payments.Provider
	Orders   *orders.Service
	Delivery *delivery.Service
	Store    storage.Store
	Audit    *audit.Service
	Limiter  *ratelimit.Local

	Server *api.Server
}

// Options lets tests substitute the clock and the payment provider without
// changing any production wiring.
type Options struct {
	Clock clock.Clock
	// Provider overrides the configured payment adapter. Only the end-to-end
	// suite uses it, to point the real adapter at a local protocol simulator.
	Provider payments.Provider
	// Argon lets the suite use cheaper password parameters. Production refuses
	// this: Build rejects it when APP_ENV=production.
	Argon *cryptox.Argon2idParams
	// Storage overrides the object store, used by tests with a temp directory.
	Storage storage.Store
	// SkipMigrations is for tests that manage their own schema.
	SkipMigrations bool
}

// Build constructs the whole application.
func Build(ctx context.Context, cfg *config.Config, opts Options) (*App, error) {
	if opts.Clock == nil {
		opts.Clock = clock.System()
	}
	log := logx.New(logx.Options{
		Level:   logx.ParseLevel(cfg.Observe.LogLevel),
		Service: "marketplace", Version: cfg.Version, Env: string(cfg.Env),
	})
	registry := metrics.NewRegistry()
	m := metrics.NewApp(registry)

	database, err := db.Open(ctx, cfg.Database, m)
	if err != nil {
		return nil, fmt.Errorf("app: open database: %w", err)
	}

	if !opts.SkipMigrations {
		migrations, err := migrate.Embedded()
		if err != nil {
			database.Close()
			return nil, err
		}
		res, err := migrate.Up(ctx, database.Pool(), migrations)
		if err != nil {
			database.Close()
			return nil, fmt.Errorf("app: migrate: %w", err)
		}
		if len(res.Applied) > 0 {
			log.Info("schema migrated", slog.Int("applied", len(res.Applied)))
		}
	}

	vault, err := identity.NewVault(cfg.Security.DataKEK)
	if err != nil {
		database.Close()
		return nil, err
	}

	argon := cryptox.DefaultArgon2idParams
	if opts.Argon != nil {
		if cfg.Env.IsProduction() {
			database.Close()
			return nil, fmt.Errorf("app: reduced password-hashing parameters are not permitted in production")
		}
		argon = *opts.Argon
	}

	limiter := ratelimit.NewLocal(opts.Clock)
	auditSvc := audit.New()

	identitySvc, err := identity.NewService(identity.Options{
		DB: database, Vault: vault, Clock: opts.Clock, Security: cfg.Security,
		Argon: argon, Limiter: limiter, Audit: auditSvc, Metrics: m,
	})
	if err != nil {
		database.Close()
		return nil, err
	}

	ledgerSvc := ledger.NewWithClock(m, opts.Clock)

	provider := opts.Provider
	if provider == nil {
		provider, err = payments.Build(cfg.Payments, m)
		if err != nil {
			database.Close()
			return nil, err
		}
	}

	store := opts.Storage
	if store == nil {
		switch cfg.Storage.Driver {
		case "s3":
			store, err = storage.NewS3(cfg.Storage, opts.Clock)
		default:
			store, err = storage.NewFilesystem(cfg.Storage.LocalRoot, opts.Clock)
		}
		if err != nil {
			database.Close()
			return nil, err
		}
	}

	taxPolicy := tax.DefaultPolicy()
	taxPolicy.GSTBps = cfg.Tax.GSTBps
	taxPolicy.CommissionGSTBps = cfg.Tax.GSTBps
	taxPolicy.TCSBps = cfg.Tax.TCSBps
	taxPolicy.TDSBps = cfg.Tax.TDS194OBps
	taxPolicy.TDSNoPANBps = cfg.Tax.TDS194ONoPANBps
	taxPolicy.TDSThresholdMinor = cfg.Tax.TDS194OThresholdINR * 100
	taxPolicy.PlatformStateCode = cfg.Tax.PlatformStateCode
	taxPolicy.PlatformGSTIN = cfg.Tax.PlatformGSTIN

	ordersSvc, err := orders.NewService(orders.Options{
		DB: database, Ledger: ledgerSvc, Provider: provider, TaxPolicy: taxPolicy,
		Payments: cfg.Payments, Platform: cfg.Platform, Clock: opts.Clock,
		Audit: auditSvc, Log: log, Metrics: m,
	})
	if err != nil {
		database.Close()
		return nil, err
	}

	deliverySvc, err := delivery.NewService(delivery.Options{
		DB: database, Store: store, Clock: opts.Clock, Platform: cfg.Platform,
		SignKey: cfg.Security.DownloadSignKey, Limiter: limiter,
		Audit: auditSvc, Metrics: m,
	})
	if err != nil {
		database.Close()
		return nil, err
	}

	server, err := api.New(api.Dependencies{
		Config: cfg, DB: database, Log: log, Metrics: m, Registry: registry,
		Clock: opts.Clock, Identity: identitySvc, Orders: ordersSvc,
		Delivery: deliverySvc, Ledger: ledgerSvc, Audit: auditSvc,
	})
	if err != nil {
		database.Close()
		return nil, err
	}

	log.Info("application built",
		slog.String("env", string(cfg.Env)),
		slog.String("payment_provider", provider.Name()),
		slog.String("storage_driver", store.Name()),
		slog.Bool("split_settlement", provider.Capabilities().SplitSettlement),
		slog.Int("commission_bps", int(cfg.Tax.CommissionBps)),
	)
	if !cfg.Env.IsProduction() {
		// Said plainly at boot so nobody mistakes a development deployment for
		// a production one.
		log.Warn("running with development settings: development key material may be in use and production hardening is relaxed")
	}

	return &App{
		Config: cfg, Log: log, DB: database, Metrics: m, Registry: registry,
		Clock: opts.Clock, Vault: vault, Identity: identitySvc, Ledger: ledgerSvc,
		Provider: provider, Orders: ordersSvc, Delivery: deliverySvc, Store: store,
		Audit: auditSvc, Limiter: limiter, Server: server,
	}, nil
}

// Close releases resources.
func (a *App) Close() {
	if a.DB != nil {
		a.DB.Close()
	}
}

// SweepLimiter bounds rate-limiter memory against an attacker cycling keys, and
// keeps pool statistics fresh for the metrics endpoint.
func (a *App) SweepLimiter(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.Limiter.Sweep()
			a.DB.ReportPoolStats()
		}
	}
}
