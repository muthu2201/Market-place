// Package e2e drives the real HTTP surface of the assembled application.
//
// Nothing is stubbed inside the process: the router, middleware, CSRF, session
// cookies, authorisation, the tax engine, the double-entry ledger, the payment
// adapter and PostgreSQL are all the production code paths. The only substitute
// is at the network boundary, where a local server speaks the payment
// provider's wire protocol so the suite can run without a third party.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/app"
	"github.com/muthu2201/market-place/internal/modules/payments"
	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/cryptox"
	"github.com/muthu2201/market-place/internal/platform/dbtest"
	"github.com/muthu2201/market-place/internal/storage"
	"github.com/muthu2201/market-place/internal/testsupport/gatewaysim"
)

type env struct {
	t       *testing.T
	app     *app.App
	server  *httptest.Server
	gateway *gatewaysim.Harness
	clk     *clock.Fixed
	store   storage.Store
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.Fresh(t)
	gw := gatewaysim.Start(t)

	provider, err := payments.NewRazorpay(payments.RazorpayConfig{
		BaseURL: gw.URL(), KeyID: gw.Cfg.KeyID, KeySecret: gw.Cfg.KeySecret,
		WebhookSecret: gw.Cfg.WebhookSecret, RouteMode: true,
		Timeout: 10 * time.Second, MaxRetries: 1, AllowPrivateHosts: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	store, err := storage.NewFilesystem(t.TempDir(), clock.System())
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFixed(time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC))

	// Configuration is loaded exactly as production does, from the environment,
	// so the loader's validation is part of what the suite exercises.
	setenv(t, map[string]string{
		"APP_ENV":             "test",
		"APP_PUBLIC_BASE_URL": "http://127.0.0.1:8080",
		"DATABASE_URL":        dbtest.EffectiveURL(t),
		"PAYMENTS_PROVIDER":   "bridge",
		"STORAGE_DRIVER":      "filesystem",
		"MAIL_DRIVER":         "log",
		"PLATFORM_GSTIN":      "33AAAAA0000A1Z5",
		"PLATFORM_STATE_CODE": "33",
		"COMMISSION_BPS":      "900",
		"METRICS_TOKEN":       "test-metrics-token",
	})
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("configuration failed to load: %v", err)
	}

	argon := cryptox.TestArgon2idParams
	application, err := app.Build(context.Background(), cfg, app.Options{
		Clock: clk, Provider: provider, Argon: &argon, Storage: store, SkipMigrations: true,
	})
	if err != nil {
		t.Fatalf("application failed to build: %v", err)
	}
	t.Cleanup(application.Close)
	_ = d

	srv := httptest.NewServer(application.Server.Handler())
	t.Cleanup(srv.Close)

	return &env{t: t, app: application, server: srv, gateway: gw, clk: clk, store: store}
}

func setenv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		old, had := os.LookupEnv(k)
		if err := os.Setenv(k, v); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if had {
				_ = os.Setenv(k, old)
			} else {
				_ = os.Unsetenv(k)
			}
		})
	}
}

// client is a browser-like HTTP client: it keeps cookies and carries the CSRF
// token, exactly as a real front end must.
type client struct {
	t    *testing.T
	env  *env
	http *http.Client
	csrf string
}

func (e *env) newClient() *client {
	e.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		e.t.Fatal(err)
	}
	c := &client{t: e.t, env: e, http: &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
	c.refreshCSRF()
	return c
}

func (c *client) refreshCSRF() {
	c.t.Helper()
	var out struct {
		CSRFToken string `json:"csrf_token"`
	}
	c.do(http.MethodGet, "/api/v1/auth/session", nil, &out)
	c.csrf = out.CSRFToken
}

type response struct {
	Status int
	Body   []byte
	Header http.Header
}

func (c *client) do(method, path string, body any, out any) response {
	c.t.Helper()
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("encode request: %v", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, c.env.server.URL+path, reader)
	if err != nil {
		c.t.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	// A real browser sends this on a same-origin fetch; the CSRF middleware
	// checks it as the second half of its defence.
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", c.env.server.URL)

	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			c.t.Fatalf("%s %s: decode %d response: %v\nbody: %s", method, path, resp.StatusCode, err, raw)
		}
	}
	return response{Status: resp.StatusCode, Body: raw, Header: resp.Header}
}

// doRaw sends a request without the CSRF token or origin headers, used to prove
// the protections actually fire.
func (c *client) doRaw(method, path string, body any, headers map[string]string) response {
	c.t.Helper()
	var reader io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, c.env.server.URL+path, reader)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return response{Status: resp.StatusCode, Body: raw, Header: resp.Header}
}

func (c *client) mustOK(r response, context string) {
	c.t.Helper()
	if r.Status < 200 || r.Status >= 300 {
		c.t.Fatalf("%s: expected success, got %d: %s", context, r.Status, r.Body)
	}
}

func (c *client) register(email, password string) {
	c.t.Helper()
	r := c.do(http.MethodPost, "/api/v1/auth/register", map[string]any{
		"email": email, "password": password, "display_name": "Test Buyer",
		"country": "IN", "state_code": 33, "accept_notice_version": "2026-01-01",
	}, nil)
	c.mustOK(r, "register")
}

func (c *client) login(email, password string) response {
	c.t.Helper()
	r := c.do(http.MethodPost, "/api/v1/auth/login", map[string]any{
		"email": email, "password": password,
	}, nil)
	c.refreshCSRF()
	return r
}

func jsonPath(t *testing.T, body []byte, path string) any {
	t.Helper()
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, body)
	}
	cur := doc
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %q: %q is not an object\nbody: %s", path, seg, body)
		}
		cur, ok = m[seg]
		if !ok {
			t.Fatalf("path %q: %q is absent\nbody: %s", path, seg, body)
		}
	}
	return cur
}

func jsonString(t *testing.T, body []byte, path string) string {
	t.Helper()
	v, ok := jsonPath(t, body, path).(string)
	if !ok {
		t.Fatalf("path %q is not a string\nbody: %s", path, body)
	}
	return v
}

var _ = fmt.Sprint
var _ = url.Parse
