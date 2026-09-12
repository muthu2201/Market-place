package api

import (
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/ratelimit"
)

// TestOpenAPIMatchesRoutes compares docs/api/openapi.yaml against the routes the
// server actually registers.
//
// A specification that has drifted from the router is worse than no
// specification: a client trusts it and is wrong. Adding a public endpoint
// without documenting it, or documenting one that does not exist, fails here.
//
// Admin and internal-verification endpoints are deliberately excluded: they are
// operator surfaces behind a role or an internal token, and publishing them
// would tell an attacker exactly where to aim.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	registered := publicRoutes(t)
	documented := documentedRoutes(t)

	for _, r := range registered {
		if !contains(documented, r) {
			t.Errorf("route %q is served but not documented in docs/api/openapi.yaml", r)
		}
	}
	for _, d := range documented {
		if !contains(registered, d) {
			t.Errorf("route %q is documented in docs/api/openapi.yaml but not served", d)
		}
	}
	if t.Failed() {
		t.Logf("served:\n  %s", strings.Join(registered, "\n  "))
		t.Logf("documented:\n  %s", strings.Join(documented, "\n  "))
	}
}

// publicRoutes builds the route table and drops the operator surfaces.
//
// routes() needs configuration and a limiter but never calls a handler, so the
// services may be nil: this exercises registration only.
func publicRoutes(t *testing.T) []string {
	t.Helper()
	s := testServer(t)
	_ = s.routes()

	var out []string
	for _, p := range s.registered {
		if strings.Contains(p, "/internal/") || strings.Contains(p, "/api/v1/admin/") {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// documentedRoutes reads the path and method keys out of the specification.
//
// This is a deliberately small scanner rather than a YAML dependency: the
// module list is kept short on purpose, and a test helper is not a good reason
// to lengthen it. It relies only on the two-space path / four-space method
// indentation the file uses throughout.
func documentedRoutes(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read specification: %v", err)
	}

	methods := map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true}
	var out []string
	var inPaths bool
	var path string

	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			inPaths = strings.HasPrefix(line, "paths:")
			path = ""
			continue
		}
		if !inPaths {
			continue
		}
		trimmed := strings.TrimSpace(line)
		switch indent := len(line) - len(strings.TrimLeft(line, " ")); {
		case indent == 2 && strings.HasPrefix(trimmed, "/") && strings.HasSuffix(trimmed, ":"):
			path = strings.TrimSuffix(trimmed, ":")
		case indent == 4 && path != "":
			key := strings.TrimSuffix(trimmed, ":")
			if methods[key] {
				out = append(out, strings.ToUpper(key)+" "+path)
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no paths parsed from the specification; the scanner or the file layout changed")
	}
	sort.Strings(out)
	return out
}

// testServer builds a Server with configuration and a limiter but no services.
//
// routes() never calls a handler, so nil services exercise registration only.
// Handlers that need a service take one explicitly in their own tests.
func testServer(t *testing.T) *Server {
	t.Helper()
	base, err := url.Parse("https://example.test")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		cfg: &config.Config{
			HTTP: config.HTTPConfig{
				PublicBaseURL: base, AllowedOrigins: []string{"https://example.test"},
				MaxRequestBytes: 1 << 20, WriteTimeout: 30 * time.Second,
			},
			Security: config.SecurityConfig{
				CSRFKey: make([]byte, 32), SecureCookies: true, HSTSMaxAge: 180 * 24 * time.Hour,
			},
		},
		clk:       clock.System(),
		limiter:   ratelimit.NewLocal(clock.System()),
		startedAt: clock.System().Now(),
	}
	s.rules = rulesFrom(s.cfg.Limits)
	return s
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
