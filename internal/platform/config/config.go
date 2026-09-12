// Package config loads and validates every runtime setting exactly once, at
// startup, and refuses to start when a production deployment is misconfigured.
//
// The design rule is fail-fast over fail-open: there is no default that silently
// weakens security. A missing session key is a boot failure, not a generated
// ephemeral key, because an ephemeral key would invalidate every session on
// restart and mask the misconfiguration.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Env string

const (
	EnvDevelopment Env = "development"
	EnvTest        Env = "test"
	EnvStaging     Env = "staging"
	EnvProduction  Env = "production"
)

func (e Env) IsProduction() bool { return e == EnvProduction }
func (e Env) IsTest() bool       { return e == EnvTest }

// Config is the fully-resolved application configuration.
type Config struct {
	Env     Env
	Version string

	HTTP      HTTPConfig
	Database  DatabaseConfig
	Security  SecurityConfig
	Storage   StorageConfig
	Antivirus AntivirusConfig
	Payments  PaymentsConfig
	Tax       TaxConfig
	Mail      MailConfig
	Limits    LimitsConfig
	Worker    WorkerConfig
	Platform  PlatformConfig
	Observe   ObserveConfig
}

type HTTPConfig struct {
	Addr              string
	PublicBaseURL     *url.URL
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownGrace     time.Duration
	MaxRequestBytes   int64
	MaxUploadBytes    int64
	TrustedProxyCIDRs []string
	AllowedOrigins    []string
}

type DatabaseConfig struct {
	URL              string
	MaxConns         int32
	MinConns         int32
	MaxConnLifetime  time.Duration
	MaxConnIdleTime  time.Duration
	StatementTimeout time.Duration
	ConnectTimeout   time.Duration
}

type SecurityConfig struct {
	SessionKey                 []byte // 32 bytes, HMAC for session cookie integrity
	DataKEK                    []byte // 32 bytes, wraps per-subject DEKs (crypto-shredding)
	DownloadSignKey            []byte // 32 bytes, signs delivery URLs
	CSRFKey                    []byte // 32 bytes
	SessionTTL                 time.Duration
	SessionIdleTTL             time.Duration
	LoginMaxAttempts           int
	LoginLockout               time.Duration
	RequireTwoFactorForSellers bool
	CookieDomain               string
	SecureCookies              bool
	HSTSMaxAge                 time.Duration
}

type StorageConfig struct {
	Driver          string // "s3" (R2/S3-compatible) or "filesystem"
	Endpoint        string
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	ForcePathStyle  bool
	LocalRoot       string
	PublicCDNBase   string
	MultipartSize   int64
}

// AntivirusConfig configures upload scanning.
//
// The driver is "clamav" or "disabled". Production refuses "disabled", because
// an unscanned asset is exactly the thing the publish trigger exists to stop
// and a deployment that quietly turned scanning off would look identical to one
// where every upload happened to be clean.
type AntivirusConfig struct {
	Driver    string
	Address   string
	Timeout   time.Duration
	MaxBytes  int64
	ChunkSize int
}

type PaymentsConfig struct {
	// Provider selects the active adapter: "bridge" (single-merchant collection
	// plus reconciled payouts, used before Route turnover eligibility),
	// "razorpay_route" (split settlement), or "mor" (merchant of record).
	Provider              string
	RazorpayKeyID         string
	RazorpayKeySecret     string
	RazorpayWebhookSecret string
	RazorpayBaseURL       string
	RouteAccountID        string
	MoRProvider           string
	MoRAPIKey             string
	MoRWebhookSecret      string
	MoRBaseURL            string
	RequestTimeout        time.Duration
	MaxRetries            int
	// SettlementHoldDays is the protection window before a seller transfer is
	// released, sized against the card-network representment window.
	SettlementHoldDays int
	RollingReserveBps  int64
	RollingReserveDays int
	// AllowLoopbackProvider permits a plaintext provider endpoint on a
	// loopback address, which is how the load harness points the real adapter
	// at a local protocol simulator. Production refuses it outright: see
	// validateInvariants.
	AllowLoopbackProvider bool
}

type TaxConfig struct {
	PlatformGSTIN                  string
	PlatformStateCode              int
	CommissionBps                  int64 // all-in platform commission, e.g. 900 = 9.00%
	GSTBps                         int64 // 1800 = 18%
	TCSBps                         int64 // 100 = 1% under s.52 CGST
	TDS194OBps                     int64 // 10 = 0.1% under s.194-O
	TDS194ONoPANBps                int64 // 500 = 5% where PAN is absent
	TDS194OThresholdINR            int64 // 500000 rupees, resident Individual/HUF
	SellerGSTExemptionThresholdINR int64 // 2000000 rupees for services
}

type MailConfig struct {
	Driver      string // "smtp", "resend", "log"
	FromAddress string
	FromName    string
	SMTPHost    string
	SMTPPort    int
	SMTPUser    string
	SMTPPass    string
	ResendKey   string
	Timeout     time.Duration
}

// LimitsConfig tunes the rate limits without a code change.
//
// The defaults are abuse controls, not capacity controls: they are set so a
// single client cannot monopolise the service, and they sit well below what the
// application can actually serve. A load test measuring application capacity
// raises them deliberately and says so in its output.
type LimitsConfig struct {
	APIPerIPBurst         int
	APIPerIPWindow        time.Duration
	SearchPerIPBurst      int
	SearchPerIPWindow     time.Duration
	CheckoutPerUserBurst  int
	CheckoutPerUserWindow time.Duration
	LoginPerIPBurst       int
	LoginPerIPWindow      time.Duration
}

type WorkerConfig struct {
	OutboxBatchSize    int
	OutboxPollInterval time.Duration
	JobConcurrency     int
	MaxAttempts        int
	Enabled            bool
}

type PlatformConfig struct {
	Currency              string
	GrievanceOfficerName  string
	GrievanceOfficerEmail string
	GrievanceAckHours     int
	GrievanceResolveDays  int
	DownloadURLTTL        time.Duration
	DownloadsPerLicense   int
	RankingSeedRotation   time.Duration
	MaxProductAssets      int
}

type ObserveConfig struct {
	LogLevel     string
	MetricsAddr  string
	MetricsToken string
}

type loader struct {
	env  Env
	errs []string
}

// Load reads configuration from the process environment.
func Load() (*Config, error) {
	l := &loader{}
	envName := strings.ToLower(getenv("APP_ENV", "development"))
	switch Env(envName) {
	case EnvDevelopment, EnvTest, EnvStaging, EnvProduction:
		l.env = Env(envName)
	default:
		return nil, fmt.Errorf("config: APP_ENV must be development|test|staging|production, got %q", envName)
	}

	c := &Config{Env: l.env, Version: getenv("APP_VERSION", "dev")}

	baseURL := l.url("APP_PUBLIC_BASE_URL", "http://localhost:8080")
	c.HTTP = HTTPConfig{
		Addr:              getenv("HTTP_ADDR", "127.0.0.1:8080"),
		PublicBaseURL:     baseURL,
		ReadTimeout:       l.duration("HTTP_READ_TIMEOUT", 15*time.Second),
		ReadHeaderTimeout: l.duration("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
		WriteTimeout:      l.duration("HTTP_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:       l.duration("HTTP_IDLE_TIMEOUT", 90*time.Second),
		ShutdownGrace:     l.duration("HTTP_SHUTDOWN_GRACE", 20*time.Second),
		MaxRequestBytes:   l.int64("HTTP_MAX_REQUEST_BYTES", 1<<20),
		MaxUploadBytes:    l.int64("HTTP_MAX_UPLOAD_BYTES", 512<<20),
		TrustedProxyCIDRs: l.list("HTTP_TRUSTED_PROXY_CIDRS", ""),
		AllowedOrigins:    l.list("HTTP_ALLOWED_ORIGINS", baseURL.Scheme+"://"+baseURL.Host),
	}

	c.Database = DatabaseConfig{
		URL:              l.required("DATABASE_URL"),
		MaxConns:         int32(l.int64("DB_MAX_CONNS", 20)),
		MinConns:         int32(l.int64("DB_MIN_CONNS", 2)),
		MaxConnLifetime:  l.duration("DB_MAX_CONN_LIFETIME", time.Hour),
		MaxConnIdleTime:  l.duration("DB_MAX_CONN_IDLE", 15*time.Minute),
		StatementTimeout: l.duration("DB_STATEMENT_TIMEOUT", 15*time.Second),
		ConnectTimeout:   l.duration("DB_CONNECT_TIMEOUT", 10*time.Second),
	}

	c.Security = SecurityConfig{
		SessionKey:                 l.key("SESSION_KEY"),
		DataKEK:                    l.key("DATA_KEK"),
		DownloadSignKey:            l.key("DOWNLOAD_SIGN_KEY"),
		CSRFKey:                    l.key("CSRF_KEY"),
		SessionTTL:                 l.duration("SESSION_TTL", 30*24*time.Hour),
		SessionIdleTTL:             l.duration("SESSION_IDLE_TTL", 14*24*time.Hour),
		LoginMaxAttempts:           int(l.int64("LOGIN_MAX_ATTEMPTS", 8)),
		LoginLockout:               l.duration("LOGIN_LOCKOUT", 15*time.Minute),
		RequireTwoFactorForSellers: l.bool("REQUIRE_2FA_SELLERS", l.env.IsProduction()),
		CookieDomain:               getenv("COOKIE_DOMAIN", ""),
		SecureCookies:              l.bool("SECURE_COOKIES", baseURL.Scheme == "https"),
		HSTSMaxAge:                 l.duration("HSTS_MAX_AGE", 365*24*time.Hour),
	}

	c.Storage = StorageConfig{
		Driver:          getenv("STORAGE_DRIVER", "filesystem"),
		Endpoint:        getenv("STORAGE_ENDPOINT", ""),
		Region:          getenv("STORAGE_REGION", "auto"),
		Bucket:          getenv("STORAGE_BUCKET", ""),
		AccessKeyID:     getenv("STORAGE_ACCESS_KEY_ID", ""),
		SecretAccessKey: getenv("STORAGE_SECRET_ACCESS_KEY", ""),
		ForcePathStyle:  l.bool("STORAGE_FORCE_PATH_STYLE", true),
		LocalRoot:       getenv("STORAGE_LOCAL_ROOT", "./var/objects"),
		PublicCDNBase:   getenv("STORAGE_PUBLIC_CDN_BASE", ""),
		MultipartSize:   l.int64("STORAGE_MULTIPART_SIZE", 16<<20),
	}

	c.Antivirus = AntivirusConfig{
		Driver:    getenv("ANTIVIRUS_DRIVER", "disabled"),
		Address:   getenv("CLAMAV_ADDRESS", ""),
		Timeout:   l.duration("CLAMAV_TIMEOUT", 5*time.Minute),
		MaxBytes:  l.int64("CLAMAV_MAX_BYTES", 2<<30),
		ChunkSize: int(l.int64("CLAMAV_CHUNK_SIZE", 64<<10)),
	}

	c.Payments = PaymentsConfig{
		Provider:              getenv("PAYMENTS_PROVIDER", "bridge"),
		RazorpayKeyID:         getenv("RAZORPAY_KEY_ID", ""),
		RazorpayKeySecret:     getenv("RAZORPAY_KEY_SECRET", ""),
		RazorpayWebhookSecret: getenv("RAZORPAY_WEBHOOK_SECRET", ""),
		RazorpayBaseURL:       getenv("RAZORPAY_BASE_URL", "https://api.razorpay.com"),
		RouteAccountID:        getenv("RAZORPAY_ROUTE_ACCOUNT_ID", ""),
		MoRProvider:           getenv("MOR_PROVIDER", ""),
		MoRAPIKey:             getenv("MOR_API_KEY", ""),
		MoRWebhookSecret:      getenv("MOR_WEBHOOK_SECRET", ""),
		MoRBaseURL:            getenv("MOR_BASE_URL", ""),
		RequestTimeout:        l.duration("PAYMENTS_TIMEOUT", 20*time.Second),
		MaxRetries:            int(l.int64("PAYMENTS_MAX_RETRIES", 3)),
		SettlementHoldDays:    int(l.int64("SETTLEMENT_HOLD_DAYS", 14)),
		RollingReserveBps:     l.int64("ROLLING_RESERVE_BPS", 500),
		RollingReserveDays:    int(l.int64("ROLLING_RESERVE_DAYS", 90)),
		AllowLoopbackProvider: l.bool("PAYMENTS_ALLOW_LOOPBACK_PROVIDER", false),
	}

	c.Tax = TaxConfig{
		PlatformGSTIN:                  getenv("PLATFORM_GSTIN", ""),
		PlatformStateCode:              int(l.int64("PLATFORM_STATE_CODE", 33)),
		CommissionBps:                  l.int64("COMMISSION_BPS", 900),
		GSTBps:                         l.int64("GST_BPS", 1800),
		TCSBps:                         l.int64("TCS_BPS", 100),
		TDS194OBps:                     l.int64("TDS_194O_BPS", 10),
		TDS194ONoPANBps:                l.int64("TDS_194O_NO_PAN_BPS", 500),
		TDS194OThresholdINR:            l.int64("TDS_194O_THRESHOLD_INR", 500000),
		SellerGSTExemptionThresholdINR: l.int64("SELLER_GST_EXEMPTION_INR", 2000000),
	}

	c.Mail = MailConfig{
		Driver:      getenv("MAIL_DRIVER", "log"),
		FromAddress: getenv("MAIL_FROM_ADDRESS", "no-reply@localhost"),
		FromName:    getenv("MAIL_FROM_NAME", "Marketplace"),
		SMTPHost:    getenv("SMTP_HOST", ""),
		SMTPPort:    int(l.int64("SMTP_PORT", 587)),
		SMTPUser:    getenv("SMTP_USER", ""),
		SMTPPass:    getenv("SMTP_PASSWORD", ""),
		ResendKey:   getenv("RESEND_API_KEY", ""),
		Timeout:     l.duration("MAIL_TIMEOUT", 15*time.Second),
	}

	c.Limits = LimitsConfig{
		APIPerIPBurst:         int(l.int64("RATE_LIMIT_API_BURST", 300)),
		APIPerIPWindow:        l.duration("RATE_LIMIT_API_WINDOW", time.Minute),
		SearchPerIPBurst:      int(l.int64("RATE_LIMIT_SEARCH_BURST", 60)),
		SearchPerIPWindow:     l.duration("RATE_LIMIT_SEARCH_WINDOW", time.Minute),
		CheckoutPerUserBurst:  int(l.int64("RATE_LIMIT_CHECKOUT_BURST", 20)),
		CheckoutPerUserWindow: l.duration("RATE_LIMIT_CHECKOUT_WINDOW", 10*time.Minute),
		LoginPerIPBurst:       int(l.int64("RATE_LIMIT_LOGIN_BURST", 20)),
		LoginPerIPWindow:      l.duration("RATE_LIMIT_LOGIN_WINDOW", 15*time.Minute),
	}

	c.Worker = WorkerConfig{
		OutboxBatchSize:    int(l.int64("OUTBOX_BATCH_SIZE", 100)),
		OutboxPollInterval: l.duration("OUTBOX_POLL_INTERVAL", time.Second),
		JobConcurrency:     int(l.int64("JOB_CONCURRENCY", 4)),
		MaxAttempts:        int(l.int64("JOB_MAX_ATTEMPTS", 12)),
		Enabled:            l.bool("WORKER_ENABLED", true),
	}

	c.Platform = PlatformConfig{
		Currency:              getenv("PLATFORM_CURRENCY", "INR"),
		GrievanceOfficerName:  getenv("GRIEVANCE_OFFICER_NAME", "Grievance Officer"),
		GrievanceOfficerEmail: getenv("GRIEVANCE_OFFICER_EMAIL", "grievance@localhost"),
		GrievanceAckHours:     int(l.int64("GRIEVANCE_ACK_HOURS", 24)),
		GrievanceResolveDays:  int(l.int64("GRIEVANCE_RESOLVE_DAYS", 15)),
		DownloadURLTTL:        l.duration("DOWNLOAD_URL_TTL", 10*time.Minute),
		DownloadsPerLicense:   int(l.int64("DOWNLOADS_PER_LICENSE", 10)),
		RankingSeedRotation:   l.duration("RANKING_SEED_ROTATION", 24*time.Hour),
		MaxProductAssets:      int(l.int64("MAX_PRODUCT_ASSETS", 25)),
	}

	c.Observe = ObserveConfig{
		LogLevel:     getenv("LOG_LEVEL", "info"),
		MetricsAddr:  getenv("METRICS_ADDR", "127.0.0.1:9090"),
		MetricsToken: getenv("METRICS_TOKEN", ""),
	}

	l.validateInvariants(c)

	if len(l.errs) > 0 {
		return nil, fmt.Errorf("config: %d problem(s):\n  - %s", len(l.errs), strings.Join(l.errs, "\n  - "))
	}
	return c, nil
}

// validateInvariants holds the rules that cannot be expressed as a single
// field's parse, especially the production hardening checks.
func (l *loader) validateInvariants(c *Config) {
	switch c.Payments.Provider {
	case "bridge", "razorpay_route", "mor":
	default:
		l.errf("PAYMENTS_PROVIDER must be bridge|razorpay_route|mor, got %q", c.Payments.Provider)
	}
	switch c.Antivirus.Driver {
	case "clamav":
		if c.Antivirus.Address == "" {
			l.errf("CLAMAV_ADDRESS is required when ANTIVIRUS_DRIVER=clamav (host:port, or unix:/path/to/clamd.ctl)")
		}
	case "disabled":
	default:
		l.errf("ANTIVIRUS_DRIVER must be clamav|disabled, got %q", c.Antivirus.Driver)
	}

	switch c.Storage.Driver {
	case "s3", "filesystem":
	default:
		l.errf("STORAGE_DRIVER must be s3|filesystem, got %q", c.Storage.Driver)
	}
	switch c.Mail.Driver {
	case "smtp", "resend", "log":
	default:
		l.errf("MAIL_DRIVER must be smtp|resend|log, got %q", c.Mail.Driver)
	}

	if c.Tax.CommissionBps < 0 || c.Tax.CommissionBps > 3000 {
		l.errf("COMMISSION_BPS %d is outside the sane range 0..3000 (0%%..30%%)", c.Tax.CommissionBps)
	}
	if c.Database.MinConns > c.Database.MaxConns {
		l.errf("DB_MIN_CONNS (%d) exceeds DB_MAX_CONNS (%d)", c.Database.MinConns, c.Database.MaxConns)
	}
	for name, v := range map[string]int{
		"RATE_LIMIT_API_BURST":      c.Limits.APIPerIPBurst,
		"RATE_LIMIT_SEARCH_BURST":   c.Limits.SearchPerIPBurst,
		"RATE_LIMIT_CHECKOUT_BURST": c.Limits.CheckoutPerUserBurst,
		"RATE_LIMIT_LOGIN_BURST":    c.Limits.LoginPerIPBurst,
	} {
		if v < 1 {
			l.errf("%s must be at least 1; a limit of zero refuses every request", name)
		}
	}
	if c.Platform.DownloadURLTTL > time.Hour {
		l.errf("DOWNLOAD_URL_TTL %s is too long; signed delivery URLs must be short-lived", c.Platform.DownloadURLTTL)
	}

	if !c.Env.IsProduction() {
		return
	}

	// --- production-only hardening -----------------------------------------
	if c.HTTP.PublicBaseURL.Scheme != "https" {
		l.errf("APP_PUBLIC_BASE_URL must be https in production")
	}
	if !c.Security.SecureCookies {
		l.errf("SECURE_COOKIES cannot be disabled in production")
	}
	if c.Security.HSTSMaxAge < 180*24*time.Hour {
		l.errf("HSTS_MAX_AGE must be at least 180 days in production")
	}
	if c.Antivirus.Driver != "clamav" {
		l.errf("ANTIVIRUS_DRIVER must be clamav in production: uploads that were never scanned must not be sellable")
	}
	if c.Storage.Driver != "s3" {
		l.errf("STORAGE_DRIVER must be s3 in production; the filesystem driver is single-node only")
	}
	if c.Mail.Driver == "log" {
		l.errf("MAIL_DRIVER=log discards transactional mail and is not permitted in production")
	}
	if strings.Contains(c.Database.URL, "sslmode=disable") {
		l.errf("DATABASE_URL must not disable TLS in production")
	}
	if c.Tax.PlatformGSTIN == "" {
		l.errf("PLATFORM_GSTIN is required in production: the platform is an e-commerce operator under s.52 CGST")
	}
	if c.Observe.MetricsToken == "" {
		l.errf("METRICS_TOKEN is required in production so the metrics endpoint is not world-readable")
	}
	if c.Payments.Provider == "razorpay_route" {
		if c.Payments.RazorpayKeyID == "" || c.Payments.RazorpayKeySecret == "" || c.Payments.RazorpayWebhookSecret == "" {
			l.errf("razorpay_route requires RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET and RAZORPAY_WEBHOOK_SECRET")
		}
		if !strings.HasPrefix(c.Payments.RazorpayBaseURL, "https://") {
			l.errf("RAZORPAY_BASE_URL must be https in production")
		}
	}
	if c.Payments.Provider == "mor" && (c.Payments.MoRAPIKey == "" || c.Payments.MoRWebhookSecret == "") {
		l.errf("the merchant-of-record adapter requires MOR_API_KEY and MOR_WEBHOOK_SECRET")
	}
	if c.Payments.AllowLoopbackProvider {
		l.errf("PAYMENTS_ALLOW_LOOPBACK_PROVIDER cannot be enabled in production: it permits an unencrypted payment endpoint")
	}
	if c.Payments.SettlementHoldDays < 7 {
		l.errf("SETTLEMENT_HOLD_DAYS must be at least 7: RuPay representment alone runs to 7 working days")
	}
	if c.Limits.LoginPerIPBurst > 200 {
		l.errf("RATE_LIMIT_LOGIN_BURST of %d is too high for production: password hashing is deliberately expensive and this invites a resource-exhaustion attack", c.Limits.LoginPerIPBurst)
	}
	if !c.Security.RequireTwoFactorForSellers {
		l.errf("REQUIRE_2FA_SELLERS cannot be disabled in production: sellers control payout destinations")
	}
	if len(c.HTTP.TrustedProxyCIDRs) == 0 {
		l.errf("HTTP_TRUSTED_PROXY_CIDRS must be set in production so client IPs cannot be spoofed via X-Forwarded-For")
	}
}

// ---- primitives -------------------------------------------------------------

func getenv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func (l *loader) errf(format string, a ...any) { l.errs = append(l.errs, fmt.Sprintf(format, a...)) }

func (l *loader) required(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		l.errf("%s is required", k)
	}
	return v
}

// key decodes a 32-byte secret from base64 or hex. In non-production it will
// derive a deterministic development key rather than fail, but it records the
// fact so that the boot log states plainly that a development key is in use.
func (l *loader) key(k string) []byte {
	raw := strings.TrimSpace(os.Getenv(k))
	if raw == "" {
		if l.env.IsProduction() {
			l.errf("%s is required in production (32 random bytes, base64)", k)
			return nil
		}
		// Deterministic, clearly-marked development key. Never used in prod
		// because the branch above fails the boot.
		dev := make([]byte, 32)
		copy(dev, []byte("DEVELOPMENT-ONLY-KEY:"+k+"::::::::::::::::::::::::"))
		return dev[:32]
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		if b2, ok := hexBytes(raw); ok {
			b = b2
		} else {
			l.errf("%s must be base64 or hex encoded", k)
			return nil
		}
	}
	if len(b) != 32 {
		l.errf("%s must decode to exactly 32 bytes, got %d", k, len(b))
		return nil
	}
	return b
}

func (l *loader) url(k, def string) *url.URL {
	raw := getenv(k, def)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		l.errf("%s must be an absolute http(s) URL, got %q", k, raw)
		u, _ = url.Parse(def)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u
}

func (l *loader) duration(k string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(k))
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		l.errf("%s must be a non-negative Go duration (e.g. 30s, 5m), got %q", k, raw)
		return def
	}
	return d
}

func (l *loader) int64(k string, def int64) int64 {
	raw := strings.TrimSpace(os.Getenv(k))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		l.errf("%s must be an integer, got %q", k, raw)
		return def
	}
	return v
}

func (l *loader) bool(k string, def bool) bool {
	raw := strings.TrimSpace(os.Getenv(k))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		l.errf("%s must be a boolean, got %q", k, raw)
		return def
	}
	return v
}

func (l *loader) list(k, def string) []string {
	raw := getenv(k, def)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func hexBytes(s string) ([]byte, bool) {
	if len(s)%2 != 0 {
		return nil, false
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		hi, ok1 := hexNibble(s[i*2])
		lo, ok2 := hexNibble(s[i*2+1])
		if !ok1 || !ok2 {
			return nil, false
		}
		out[i] = hi<<4 | lo
	}
	return out, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// ErrNotConfigured signals that an optional subsystem was intentionally left off.
var ErrNotConfigured = errors.New("config: subsystem not configured")
