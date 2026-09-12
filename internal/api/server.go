package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/muthu2201/market-place/internal/modules/audit"
	"github.com/muthu2201/market-place/internal/modules/catalog"
	"github.com/muthu2201/market-place/internal/modules/delivery"
	"github.com/muthu2201/market-place/internal/modules/identity"
	"github.com/muthu2201/market-place/internal/modules/ledger"
	"github.com/muthu2201/market-place/internal/modules/orders"
	"github.com/muthu2201/market-place/internal/modules/ranking"
	"github.com/muthu2201/market-place/internal/modules/seller"
	"github.com/muthu2201/market-place/internal/outbox"
	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/httpx"
	"github.com/muthu2201/market-place/internal/platform/logx"
	"github.com/muthu2201/market-place/internal/platform/metrics"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/platform/ratelimit"
)

// Server wires the HTTP surface to the module services.
type Server struct {
	cfg      *config.Config
	db       *db.DB
	log      *slog.Logger
	m        *metrics.App
	registry *metrics.Registry
	clk      clock.Clock

	identity *identity.Service
	orders   *orders.Service
	delivery *delivery.Service
	ledger   *ledger.Service
	audit    *audit.Service
	catalog  *catalog.Service
	seller   *seller.Service

	limiter   *ratelimit.Local
	rules     limitRules
	startedAt time.Time
	handler   http.Handler

	// registered records every route pattern as it is added, so the public API
	// surface can be compared against docs/api/openapi.yaml by a test. A
	// specification that drifts from the router is worse than none.
	registered []string

	// draining is set on SIGTERM, before the server stops accepting.
	//
	// Endpoint removal and process shutdown race: a load balancer keeps
	// sending to a pod for a second or two after it is deleted, and if the
	// process has already stopped accepting, those requests fail. Reporting
	// not-ready first, then continuing to serve for a moment, closes that
	// window from inside the application — where it belongs, rather than in a
	// preStop hook that a distroless image has no shell to run.
	draining atomic.Bool
}

// BeginDraining makes readiness fail while the server keeps serving.
//
// Call it on SIGTERM, wait for the load balancer to notice, then shut down.
func (s *Server) BeginDraining() { s.draining.Store(true) }

// RegisteredRoutes returns every route pattern the server serves, in
// registration order, as "METHOD /path".
func (s *Server) RegisteredRoutes() []string {
	out := make([]string, len(s.registered))
	copy(out, s.registered)
	return out
}

// limitRules holds the configured limits, so a handler reads one place rather
// than reaching for a package-level default.
type limitRules struct {
	api      ratelimit.Rule
	search   ratelimit.Rule
	checkout ratelimit.Rule
}

func rulesFrom(l config.LimitsConfig) limitRules {
	return limitRules{
		api:      ratelimit.Rule{Name: "api_ip", Burst: l.APIPerIPBurst, Period: l.APIPerIPWindow},
		search:   ratelimit.Rule{Name: "search_ip", Burst: l.SearchPerIPBurst, Period: l.SearchPerIPWindow},
		checkout: ratelimit.Rule{Name: "checkout_user", Burst: l.CheckoutPerUserBurst, Period: l.CheckoutPerUserWindow},
	}
}

// Dependencies is everything the HTTP layer needs. Constructing it explicitly,
// rather than reaching for a container, keeps the wiring greppable.
type Dependencies struct {
	Config   *config.Config
	DB       *db.DB
	Log      *slog.Logger
	Metrics  *metrics.App
	Registry *metrics.Registry
	Clock    clock.Clock
	Identity *identity.Service
	Orders   *orders.Service
	Delivery *delivery.Service
	Ledger   *ledger.Service
	Audit    *audit.Service
	Catalog  *catalog.Service
	Seller   *seller.Service
}

// New builds the server and its route table.
func New(d Dependencies) (*Server, error) {
	if d.Config == nil || d.DB == nil || d.Identity == nil {
		return nil, fmt.Errorf("api: config, database and identity service are required")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Clock == nil {
		d.Clock = clock.System()
	}
	if d.Audit == nil {
		d.Audit = audit.New()
	}
	s := &Server{
		cfg: d.Config, db: d.DB, log: d.Log, m: d.Metrics, registry: d.Registry,
		clk: d.Clock, identity: d.Identity, orders: d.Orders, delivery: d.Delivery,
		ledger: d.Ledger, audit: d.Audit, catalog: d.Catalog, seller: d.Seller,
		limiter: ratelimit.NewLocal(d.Clock), startedAt: d.Clock.Now(),
	}
	s.rules = rulesFrom(d.Config.Limits)
	s.handler = s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// Handler exposes the fully-wrapped handler for tests and for the server.
func (s *Server) Handler() http.Handler { return s.handler }

// routes builds the route table and the middleware chain.
//
// The chain order is a security control and is asserted by a test:
//   - Recover is outermost, so a panic anywhere still yields a correlated 500;
//   - RequestID precedes logging so every line correlates;
//   - RealIP precedes rate limiting, or limits could be defeated by a forged
//     X-Forwarded-For;
//   - rate limiting precedes authentication, so an unauthenticated flood cannot
//     force password hashing;
//   - MaxBytes precedes anything that reads a body.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	origins := s.cfg.HTTP.AllowedOrigins
	csrf := httpx.CSRF(httpx.CSRFOptions{
		Key:            s.cfg.Security.CSRFKey,
		Secure:         s.cfg.Security.SecureCookies,
		Domain:         s.cfg.Security.CookieDomain,
		TrustedOrigins: origins,
	})

	// --- public, unauthenticated -------------------------------------------
	s.route(mux, "GET /healthz", s.handleHealth)
	s.route(mux, "GET /readyz", s.handleReady)
	s.route(mux, "GET /metrics", s.handleMetrics)
	s.route(mux, "GET /.well-known/security.txt", s.handleSecurityTxt)
	s.route(mux, "GET /legal/ranking", s.handleRankingDisclosure)
	s.route(mux, "GET /legal/fees", s.handleFeeCovenant)
	s.route(mux, "GET /api/v1/catalog/products", s.handleListProducts)
	s.route(mux, "GET /api/v1/catalog/products/{id}", s.handleGetProduct)
	s.route(mux, "GET /api/v1/catalog/search", s.handleSearch)

	// --- authentication -----------------------------------------------------
	s.route(mux, "POST /api/v1/auth/register", s.handleRegister)
	s.route(mux, "POST /api/v1/auth/login", s.handleLogin)
	s.route(mux, "POST /api/v1/auth/logout", s.handleLogout)
	s.route(mux, "POST /api/v1/auth/password-reset", s.handleBeginPasswordReset)
	s.route(mux, "POST /api/v1/auth/password-reset/complete", s.handleCompletePasswordReset)
	s.route(mux, "GET /api/v1/auth/session", s.handleSession)

	// --- buyer --------------------------------------------------------------
	s.authed(mux, "POST /api/v1/checkout", s.handleCheckout)
	s.authed(mux, "POST /api/v1/orders/{id}/payment", s.handleBeginPayment)
	s.authed(mux, "POST /api/v1/orders/{id}/confirm", s.handleConfirmPayment)
	s.authed(mux, "GET /api/v1/orders", s.handleListOrders)
	s.authed(mux, "GET /api/v1/orders/{id}", s.handleGetOrder)
	s.authed(mux, "POST /api/v1/orders/{id}/refund", s.handleRequestRefund)
	s.authed(mux, "GET /api/v1/library", s.handleLibrary)
	s.authed(mux, "POST /api/v1/library/{license}/download/{asset}", s.handleIssueDownload)
	s.route(mux, "GET /downloads/{grant}", s.handleRedeemDownload)

	// --- seller ---------------------------------------------------------------
	// Onboarding is open to any authenticated account; everything after it
	// requires the seller role, which onboarding grants. Verification gates
	// publishing and settlement separately — a pending seller can build a
	// listing, they simply cannot sell it yet.
	s.authed(mux, "POST /api/v1/seller/onboard", s.handleSellerOnboard)
	s.staffed(mux, "POST /api/v1/seller/kyc/submit", s.handleSellerSubmitKYC, identity.RoleSeller)
	s.staffed(mux, "GET /api/v1/seller/payouts", s.handleSellerPayoutStatus, identity.RoleSeller)
	s.staffed(mux, "POST /api/v1/seller/payouts/accounts", s.handleSellerAddPayoutAccount, identity.RoleSeller)
	s.staffed(mux, "DELETE /api/v1/seller/payouts/accounts/{id}", s.handleSellerDisablePayoutAccount, identity.RoleSeller)

	s.staffed(mux, "POST /api/v1/seller/products", s.handleDraftProduct, identity.RoleSeller)
	s.staffed(mux, "POST /api/v1/seller/products/{id}/variants", s.handleAddVariant, identity.RoleSeller)
	s.staffed(mux, "PUT /api/v1/seller/products/{id}/tags", s.handleReplaceTags, identity.RoleSeller)
	s.staffed(mux, "POST /api/v1/seller/products/{id}/uploads", s.handleRequestUpload, identity.RoleSeller)
	s.staffed(mux, "POST /api/v1/seller/products/{id}/assets", s.handleFinaliseUpload, identity.RoleSeller)
	s.staffed(mux, "GET /api/v1/seller/products/{id}/readiness", s.handleProductReadiness, identity.RoleSeller)
	s.staffed(mux, "POST /api/v1/seller/products/{id}/publish", s.handlePublishProduct, identity.RoleSeller)
	s.staffed(mux, "POST /api/v1/seller/products/{id}/unpublish", s.handleUnpublishProduct, identity.RoleSeller)

	// --- provider webhooks --------------------------------------------------
	// Deliberately outside CSRF and authentication: the signature IS the
	// authentication, and a provider cannot send a CSRF token.
	s.route(mux, "POST /webhooks/payments", s.handlePaymentWebhook)

	// --- correctness verification ------------------------------------------
	// Gated by the operations token or a staff session. These run the system's
	// own audit of itself and are what the load harness asserts against.
	s.route(mux, "GET /internal/verify/trial-balance", s.requireInternalToken(s.handleVerifyTrialBalance))
	s.route(mux, "GET /internal/verify/audit-chain", s.requireInternalToken(s.handleVerifyAudit))
	s.route(mux, "GET /internal/verify/consistency", s.requireInternalToken(s.handleVerifyConsistency))

	// --- operations ---------------------------------------------------------
	s.staffed(mux, "GET /api/v1/admin/ledger/trial-balance", s.handleTrialBalance, identity.RoleFinanceOperator, identity.RoleAdmin)
	s.staffed(mux, "GET /api/v1/admin/audit/verify", s.handleVerifyAuditChain, identity.RoleAdmin)
	s.staffed(mux, "GET /api/v1/admin/outbox", s.handleOutboxStatus, identity.RoleAdmin, identity.RoleFinanceOperator)

	base := httpx.Chain(mux,
		httpx.Recover(s.log),
		httpx.RequestID(),
		httpx.RealIP(s.cfg.HTTP.TrustedProxyCIDRs),
		// The route cell must be installed before anything reads the route.
		httpx.WithRouteCapture(),
		httpx.Logging(s.log, s.m),
		httpx.SecurityHeaders(httpx.SecurityHeaderOptions{
			HSTSMaxAge: s.cfg.Security.HSTSMaxAge,
			EnableHSTS: s.cfg.HTTP.PublicBaseURL.Scheme == "https",
		}),
		httpx.CORS(origins),
		httpx.MaxBytes(s.cfg.HTTP.MaxRequestBytes),
		httpx.Timeout(s.cfg.HTTP.WriteTimeout-time.Second),
		httpx.RateLimit(s.limiter, s.rules.api, s.m,
			"/healthz", "/readyz", "/metrics", "/.well-known/security.txt"),
		s.authenticate,
		csrf,
	)
	return base
}

// route registers a public endpoint with its metric template.
func (s *Server) route(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	template := pattern
	if i := strings.IndexByte(pattern, ' '); i > 0 {
		template = pattern[i+1:]
	}
	s.registered = append(s.registered, pattern)
	mux.Handle(pattern, httpx.WithRoute(template, h))
}

// authed registers an endpoint requiring a fully authenticated session.
func (s *Server) authed(mux *http.ServeMux, pattern string, h http.HandlerFunc) {
	template := pattern
	if i := strings.IndexByte(pattern, ' '); i > 0 {
		template = pattern[i+1:]
	}
	s.registered = append(s.registered, pattern)
	mux.Handle(pattern, httpx.WithRoute(template, s.requireAuth(h)))
}

// staffed registers an endpoint requiring one of the named roles.
func (s *Server) staffed(mux *http.ServeMux, pattern string, h http.HandlerFunc, roles ...string) {
	template := pattern
	if i := strings.IndexByte(pattern, ' '); i > 0 {
		template = pattern[i+1:]
	}
	s.registered = append(s.registered, pattern)
	mux.Handle(pattern, httpx.WithRoute(template, s.requireRole(roles...)(h)))
}

// ---- operational endpoints --------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Liveness answers one question: is this process able to serve? It must not
	// depend on the database, or a database blip would cause the orchestrator
	// to kill healthy application instances and make an outage worse.
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": s.cfg.Version,
		"uptime":  int(s.clk.Now().Sub(s.startedAt).Seconds()),
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	// A draining instance reports not-ready while it is still serving, so the
	// load balancer stops sending new work before the process stops accepting
	// it. Liveness deliberately still passes: this instance is healthy, it is
	// just on its way out, and a failing liveness probe here would have the
	// kubelet kill it mid-drain.
	if s.draining.Load() {
		httpx.JSON(w, r, http.StatusServiceUnavailable, map[string]any{
			"status": "draining", "reason": "shutting down",
		})
		return
	}

	// Readiness otherwise depends on the database: an instance that cannot
	// reach it should be taken out of the load balancer rather than serve
	// errors.
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.db.Ping(ctx); err != nil {
		httpx.JSON(w, r, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready", "reason": "database unreachable",
		})
		return
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"status": "ready"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// Metrics reveal business volume and internal structure, so in production
	// they require a token. Without one configured, the endpoint is refused
	// rather than served openly.
	if s.cfg.Env.IsProduction() || s.cfg.Observe.MetricsToken != "" {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.cfg.Observe.MetricsToken == "" || !constantTimeEqual(token, s.cfg.Observe.MetricsToken) {
			httpx.Fail(w, r, problem.Unauthenticated("A metrics token is required."))
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if s.registry != nil {
		_, _ = s.registry.WriteTo(w)
	}
}

func (s *Server) handleSecurityTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	expires := s.clk.Now().AddDate(1, 0, 0).Format(time.RFC3339)
	fmt.Fprintf(w, `Contact: mailto:%s
Expires: %s
Preferred-Languages: en, ta, hi
Canonical: %s/.well-known/security.txt
Policy: %s/legal/security-policy

# We read every report and reply. Please give us a way to contact you.
# Please do not run load or denial-of-service tests against production.
`, s.cfg.Platform.GrievanceOfficerEmail, expires,
		s.cfg.HTTP.PublicBaseURL.String(), s.cfg.HTTP.PublicBaseURL.String())
}

func (s *Server) handleRankingDisclosure(w http.ResponseWriter, r *http.Request) {
	p := ranking.Published()
	seed := ranking.SeedFor(s.clk.Now(), p.SeedRotation)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(ranking.Disclosure(p)))
	fmt.Fprintf(w, "\nToday's published shuffle seed: %d\n", seed)
	fmt.Fprintf(w, "Formula version: %s\n", ranking.FormulaVersion)
}

func (s *Server) handleFeeCovenant(w http.ResponseWriter, r *http.Request) {
	type schedule struct {
		Code          string `json:"code"`
		CommissionBps int64  `json:"commission_bps"`
		CommissionPct string `json:"commission_percent"`
		Description   string `json:"description"`
		EffectiveFrom string `json:"effective_from"`
		AnnouncedAt   string `json:"announced_at"`
	}
	rows, err := s.db.Query(r.Context(), `
		SELECT code, commission_bps, description, effective_from::text, announced_at::text
		  FROM fee_schedules WHERE superseded_at IS NULL ORDER BY effective_from`)
	if err != nil {
		httpx.Fail(w, r, problem.Internal(err))
		return
	}
	defer rows.Close()
	var out []schedule
	for rows.Next() {
		var sc schedule
		if err := rows.Scan(&sc.Code, &sc.CommissionBps, &sc.Description, &sc.EffectiveFrom, &sc.AnnouncedAt); err != nil {
			httpx.Fail(w, r, problem.Internal(err))
			return
		}
		sc.CommissionPct = strconv.FormatFloat(float64(sc.CommissionBps)/100, 'f', 2, 64) + "%"
		out = append(out, sc)
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"covenant": []string{
			"The commission you joined on is the commission you keep. A new schedule applies to new sellers, and to existing sellers only if they choose it.",
			"Any change is announced at least 90 days before it takes effect. The database refuses to store a schedule that breaks this.",
			"Payment-processing cost and statutory tax are itemised on every statement and passed through at cost, never marked up.",
			"There are no listing fees, no monthly fees, and no charge for a payout.",
			"There is no paid placement. No position in search or on any page can be bought.",
		},
		"schedules": out,
	})
}

func (s *Server) handleTrialBalance(w http.ResponseWriter, r *http.Request) {
	rows, err := s.ledger.TrialBalance(r.Context(), s.db)
	if err != nil {
		httpx.Fail(w, r, problem.Internal(err))
		return
	}
	balanced := true
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if row.Difference != 0 {
			balanced = false
		}
		out = append(out, map[string]any{
			"currency": string(row.Currency), "total_debits_minor": row.Debits,
			"total_credits_minor": row.Credits, "difference_minor": row.Difference,
		})
	}
	status := http.StatusOK
	if !balanced {
		// A broken trial balance is an incident, and the endpoint says so
		// loudly enough for a monitor to alert on the status code alone.
		status = http.StatusInternalServerError
	}
	httpx.JSON(w, r, status, map[string]any{"balanced": balanced, "rows": out})
}

func (s *Server) handleVerifyAuditChain(w http.ResponseWriter, r *http.Request) {
	brk, err := s.audit.Verify(r.Context(), s.db, 0)
	if err != nil {
		httpx.Fail(w, r, problem.Internal(err))
		return
	}
	if brk != nil {
		httpx.JSON(w, r, http.StatusInternalServerError, map[string]any{
			"intact": false, "broken_at": brk.Seq, "reason": brk.Reason,
		})
		return
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"intact": true})
}

func (s *Server) handleOutboxStatus(w http.ResponseWriter, r *http.Request) {
	var pending, dead int
	if err := s.db.QueryRow(r.Context(), `
		SELECT count(*) FILTER (WHERE dispatched_at IS NULL AND failed_at IS NULL),
		       count(*) FILTER (WHERE failed_at IS NOT NULL)
		  FROM outbox_messages`).Scan(&pending, &dead); err != nil {
		httpx.Fail(w, r, problem.Internal(err))
		return
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{
		"pending": pending, "dead_lettered": dead,
		"topics": []string{outbox.TopicOrderPaid, outbox.TopicOrderFulfilled, outbox.TopicOrderRefunded},
	})
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		// Length is not secret here; the token is compared byte-wise below.
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// decode reads and validates a JSON body, returning false when it has already
// written an error response.
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := httpx.DecodeJSON(w, r, dst); err != nil {
		httpx.Fail(w, r, err)
		return false
	}
	return true
}

func logFrom(r *http.Request) *slog.Logger { return logx.From(r.Context()) }

var _ = json.Marshal
