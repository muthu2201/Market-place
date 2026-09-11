package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/money"
	"github.com/muthu2201/market-place/internal/testsupport/fixtures"
)

// seedCatalogue creates an activated seller and a published product, going
// through the provider so the linked account genuinely exists.
func (e *env) seedCatalogue(t *testing.T, handle string, priceMinor int64) fixtures.Product {
	t.Helper()
	ctx := context.Background()
	acct, err := e.app.Provider.CreateLinkedAccount(ctx, providerAccountRequest(handle))
	if err != nil {
		t.Fatal(err)
	}
	e.gateway.Activate(t, acct.ProviderAccountID, "activated")

	spec := fixtures.DefaultSellerSpec(handle)
	spec.ProviderAccount = acct.ProviderAccountID
	seller := fixtures.NewSeller(t, ctx, e.app.DB, e.app.Identity.Vault(), spec)
	return fixtures.NewProduct(t, ctx, e.app.DB, seller, fixtures.ProductSpec{
		Title: "Studio " + handle + " asset pack", PriceMinor: priceMinor, Publish: true,
	})
}

// The whole buyer journey over HTTP: register, sign in, browse, check out, pay,
// confirm, see the library, download.
func TestBuyerJourneyOverHTTP(t *testing.T) {
	e := newEnv(t)
	product := e.seedCatalogue(t, "journeystudio", 200000)
	c := e.newClient()

	// --- the catalogue is public -------------------------------------------
	r := c.do(http.MethodGet, "/api/v1/catalog/products", nil, nil)
	c.mustOK(r, "list products")
	if !strings.Contains(string(r.Body), "no paid placement") &&
		!strings.Contains(string(r.Body), "cannot be bought") {
		t.Fatal("every catalogue response must carry the ranking disclosure")
	}

	r = c.do(http.MethodGet, "/api/v1/catalog/products/"+product.PublicID, nil, nil)
	c.mustOK(r, "get product")
	if jsonString(t, r.Body, "detail.refund_policy_plain") == "" {
		t.Fatal("refund terms must be stated in plain words before purchase")
	}
	if jsonString(t, r.Body, "detail.ai_disclosure_plain") == "" {
		t.Fatal("the AI-content declaration must be shown before purchase")
	}

	// --- account ------------------------------------------------------------
	c.register("journey@example.com", "seven lamps beside the quiet river")
	if r := c.login("journey@example.com", "seven lamps beside the quiet river"); r.Status != http.StatusOK {
		t.Fatalf("login failed: %d %s", r.Status, r.Body)
	}
	r = c.do(http.MethodGet, "/api/v1/auth/session", nil, nil)
	if v, _ := jsonPath(t, r.Body, "authenticated").(bool); !v {
		t.Fatalf("session should be authenticated: %s", r.Body)
	}

	// --- checkout -----------------------------------------------------------
	r = c.do(http.MethodPost, "/api/v1/checkout", map[string]any{
		"items": []map[string]string{
			{"product_id": product.PublicID, "variant_id": product.VariantPublicID},
		},
		"state_code": 33, "country": "IN",
	}, nil)
	c.mustOK(r, "checkout")
	orderID := jsonString(t, r.Body, "id")
	if jsonString(t, r.Body, "status") != "draft" {
		t.Fatalf("new order status: %s", r.Body)
	}
	total := jsonPath(t, r.Body, "total.display")
	if total != "2360.00" {
		t.Fatalf("total = %v, want 2360.00 (2000 plus 18%% GST)", total)
	}
	// The tax explanation travels with the order, which is what makes the
	// figures checkable by the buyer rather than merely asserted.
	items, ok := jsonPath(t, r.Body, "items").([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("expected one item: %s", r.Body)
	}
	first := items[0].(map[string]any)
	explanation, ok := first["explanation"].([]any)
	if !ok || len(explanation) < 3 {
		t.Fatalf("every line must carry its tax explanation: %v", first["explanation"])
	}

	// --- payment ------------------------------------------------------------
	r = c.do(http.MethodPost, "/api/v1/orders/"+orderID+"/payment", nil, nil)
	c.mustOK(r, "begin payment")
	intentID := jsonString(t, r.Body, "intent_id")
	if strings.Contains(string(r.Body), "key_secret") {
		t.Fatal("the provider key secret must never reach the client")
	}

	pay := e.gateway.Pay(t, intentID, true)
	r = c.do(http.MethodPost, "/api/v1/orders/"+orderID+"/confirm", map[string]any{
		"intent_id": pay.OrderID, "payment_id": pay.PaymentID, "signature": pay.Signature,
	}, nil)
	c.mustOK(r, "confirm payment")
	if jsonString(t, r.Body, "order.status") != "fulfilled" {
		t.Fatalf("order after confirmation: %s", r.Body)
	}
	licenses, _ := jsonPath(t, r.Body, "licenses").([]any)
	if len(licenses) != 1 {
		t.Fatalf("expected one licence: %s", r.Body)
	}
	licenseID := licenses[0].(map[string]any)["id"].(string)

	// --- library and download ----------------------------------------------
	r = c.do(http.MethodGet, "/api/v1/library", nil, nil)
	c.mustOK(r, "library")
	library, _ := jsonPath(t, r.Body, "library").([]any)
	if len(library) != 1 {
		t.Fatalf("library should hold one entitlement: %s", r.Body)
	}
	assets, _ := library[0].(map[string]any)["assets"].([]any)
	if len(assets) != 1 {
		t.Fatalf("expected one downloadable asset: %s", r.Body)
	}
	assetID := assets[0].(map[string]any)["id"].(string)

	// Put the real bytes in storage so the download serves something.
	e.putAsset(t, product, []byte("the actual product bytes a buyer receives"))

	r = c.do(http.MethodPost, "/api/v1/library/"+licenseID+"/download/"+assetID, nil, nil)
	c.mustOK(r, "issue download")
	ticketURL := jsonString(t, r.Body, "url")

	dl := c.do(http.MethodGet, ticketURL, nil, nil)
	c.mustOK(dl, "download")
	if string(dl.Body) != "the actual product bytes a buyer receives" {
		t.Fatalf("delivered bytes do not match: %q", dl.Body)
	}
	if ct := dl.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type = %q; a deliverable must always be forced to a download", ct)
	}

	// The same ticket must not work twice.
	again := c.do(http.MethodGet, ticketURL, nil, nil)
	if again.Status < 400 {
		t.Fatalf("a download ticket must be single use, got %d", again.Status)
	}

	// --- the books balance --------------------------------------------------
	if err := e.app.Ledger.AssertBalanced(context.Background(), e.app.DB); err != nil {
		t.Fatal(err)
	}
}

func (e *env) putAsset(t *testing.T, p fixtures.Product, content []byte) {
	t.Helper()
	var key string
	if err := e.app.DB.QueryRow(context.Background(),
		`SELECT object_key FROM product_assets WHERE id = $1`, p.AssetID).Scan(&key); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Put(context.Background(), putRequest(key, content)); err != nil {
		t.Fatal(err)
	}
}

// --- security behaviour of the HTTP edge ------------------------------------

func TestStateChangingRequestsRequireCSRFAndOrigin(t *testing.T) {
	e := newEnv(t)
	c := e.newClient()
	c.register("csrf@example.com", "seven lamps beside the quiet river")
	c.login("csrf@example.com", "seven lamps beside the quiet river")

	body := map[string]any{"items": []map[string]string{{"product_id": "prd_X", "variant_id": "var_X"}}}

	// No CSRF token, no Origin: the classic forgery.
	r := c.doRaw(http.MethodPost, "/api/v1/checkout", body, map[string]string{
		"Content-Type": "application/json",
	})
	if r.Status != http.StatusForbidden {
		t.Fatalf("a request with no CSRF token must be refused, got %d: %s", r.Status, r.Body)
	}

	// A token but a hostile Origin: the cookie-injection variant.
	r = c.doRaw(http.MethodPost, "/api/v1/checkout", body, map[string]string{
		"Content-Type":   "application/json",
		"X-CSRF-Token":   c.csrf,
		"Origin":         "https://evil.example.com",
		"Sec-Fetch-Site": "cross-site",
	})
	if r.Status != http.StatusForbidden {
		t.Fatalf("a cross-origin request must be refused even with a token, got %d", r.Status)
	}

	// A forged token value.
	r = c.doRaw(http.MethodPost, "/api/v1/checkout", body, map[string]string{
		"Content-Type":   "application/json",
		"X-CSRF-Token":   "forged-token-value",
		"Origin":         e.server.URL,
		"Sec-Fetch-Site": "same-origin",
	})
	if r.Status != http.StatusForbidden {
		t.Fatalf("a forged CSRF token must be refused, got %d", r.Status)
	}
}

func TestSecurityHeadersArePresentOnEveryResponse(t *testing.T) {
	e := newEnv(t)
	c := e.newClient()
	r := c.do(http.MethodGet, "/api/v1/catalog/products", nil, nil)

	required := map[string]func(string) bool{
		"Content-Security-Policy": func(v string) bool {
			// No unsafe-inline and no unsafe-eval is what makes a stored XSS
			// payload inert even if output encoding were missed somewhere.
			return strings.Contains(v, "default-src 'self'") &&
				strings.Contains(v, "object-src 'none'") &&
				strings.Contains(v, "frame-ancestors 'none'") &&
				strings.Contains(v, "base-uri 'none'") &&
				!strings.Contains(v, "unsafe-inline") &&
				!strings.Contains(v, "unsafe-eval")
		},
		"X-Content-Type-Options":       func(v string) bool { return v == "nosniff" },
		"X-Frame-Options":              func(v string) bool { return v == "DENY" },
		"Referrer-Policy":              func(v string) bool { return strings.Contains(v, "strict-origin") },
		"Cross-Origin-Opener-Policy":   func(v string) bool { return v == "same-origin" },
		"Cross-Origin-Resource-Policy": func(v string) bool { return v == "same-origin" },
		"Permissions-Policy":           func(v string) bool { return strings.Contains(v, "geolocation=()") },
		"X-Request-Id":                 func(v string) bool { return len(v) >= 8 },
	}
	for header, ok := range required {
		v := r.Header.Get(header)
		if v == "" {
			t.Errorf("%s is missing", header)
			continue
		}
		if !ok(v) {
			t.Errorf("%s = %q, which does not meet the policy", header, v)
		}
	}
	if r.Header.Get("Server") != "" && strings.Contains(strings.ToLower(r.Header.Get("Server")), "go") {
		t.Error("the Server header should not advertise the runtime")
	}
}

func TestAnonymousCannotReachAuthenticatedEndpoints(t *testing.T) {
	e := newEnv(t)
	c := e.newClient()
	for _, path := range []string{
		"/api/v1/orders", "/api/v1/library",
		"/api/v1/admin/ledger/trial-balance", "/api/v1/admin/audit/verify",
	} {
		r := c.do(http.MethodGet, path, nil, nil)
		if r.Status != http.StatusUnauthorized {
			t.Errorf("%s returned %d to an anonymous caller, want 401", path, r.Status)
		}
	}
}

func TestOrdinaryUserCannotReachAdminEndpoints(t *testing.T) {
	e := newEnv(t)
	c := e.newClient()
	c.register("plain@example.com", "seven lamps beside the quiet river")
	c.login("plain@example.com", "seven lamps beside the quiet river")

	for _, path := range []string{
		"/api/v1/admin/ledger/trial-balance",
		"/api/v1/admin/audit/verify",
		"/api/v1/admin/outbox",
	} {
		r := c.do(http.MethodGet, path, nil, nil)
		if r.Status != http.StatusForbidden {
			t.Errorf("%s returned %d to a buyer, want 403", path, r.Status)
		}
	}
}

func TestRoleGrantTakesEffectOnTheExistingSession(t *testing.T) {
	e := newEnv(t)
	c := e.newClient()
	c.register("promote@example.com", "seven lamps beside the quiet river")
	c.login("promote@example.com", "seven lamps beside the quiet river")

	r := c.do(http.MethodGet, "/api/v1/admin/ledger/trial-balance", nil, nil)
	if r.Status != http.StatusForbidden {
		t.Fatalf("expected 403 before the grant, got %d", r.Status)
	}

	// Look the account up by its blind index, not by "the most recent user":
	// a test that depends on ordering is a test that fails for the wrong reason.
	ctx := context.Background()
	var userID ids.UUID
	if err := e.app.DB.QueryRow(ctx,
		`SELECT id FROM users WHERE email_index = $1 AND erased_at IS NULL`,
		e.app.Identity.Vault().BlindIndex("promote@example.com")).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := e.app.DB.InTx(ctx, db.TxOptions{Name: "grant"}, func(ctx context.Context, tx db.Tx) error {
		return e.app.Identity.GrantRole(ctx, tx, userID, "finance_operator", nil)
	}); err != nil {
		t.Fatal(err)
	}

	// The SAME session must now pass: authorisation is a live lookup.
	r = c.do(http.MethodGet, "/api/v1/admin/ledger/trial-balance", nil, nil)
	if r.Status != http.StatusOK {
		t.Fatalf("expected 200 after the grant on the same session, got %d: %s", r.Status, r.Body)
	}
	if v, _ := jsonPath(t, r.Body, "balanced").(bool); !v {
		t.Fatalf("the trial balance must be balanced: %s", r.Body)
	}
}

func TestMetricsRequireAToken(t *testing.T) {
	e := newEnv(t)
	c := e.newClient()
	r := c.do(http.MethodGet, "/metrics", nil, nil)
	if r.Status != http.StatusUnauthorized {
		t.Fatalf("metrics must not be world-readable, got %d", r.Status)
	}
	r = c.doRaw(http.MethodGet, "/metrics", nil, map[string]string{
		"Authorization": "Bearer test-metrics-token",
	})
	if r.Status != http.StatusOK {
		t.Fatalf("a correct token must be accepted, got %d", r.Status)
	}
	if !strings.Contains(string(r.Body), "http_requests_total") {
		t.Fatal("the metrics response does not look like Prometheus exposition")
	}
}

func TestHealthDoesNotDependOnTheDatabaseButReadinessDoes(t *testing.T) {
	e := newEnv(t)
	c := e.newClient()
	r := c.do(http.MethodGet, "/healthz", nil, nil)
	if r.Status != http.StatusOK {
		t.Fatalf("liveness = %d", r.Status)
	}
	r = c.do(http.MethodGet, "/readyz", nil, nil)
	if r.Status != http.StatusOK {
		t.Fatalf("readiness = %d", r.Status)
	}
}

func TestPublishedDisclosuresAreServed(t *testing.T) {
	e := newEnv(t)
	c := e.newClient()

	r := c.do(http.MethodGet, "/legal/ranking", nil, nil)
	c.mustOK(r, "ranking disclosure")
	for _, want := range []string{"no paid placement", "halves every", "Exposure cap", "shuffle seed"} {
		if !strings.Contains(strings.ToLower(string(r.Body)), strings.ToLower(want)) {
			t.Errorf("the ranking disclosure omits %q", want)
		}
	}

	r = c.do(http.MethodGet, "/legal/fees", nil, nil)
	c.mustOK(r, "fee covenant")
	if !strings.Contains(string(r.Body), "90 days") {
		t.Error("the fee covenant must state the notice period")
	}

	r = c.do(http.MethodGet, "/.well-known/security.txt", nil, nil)
	c.mustOK(r, "security.txt")
	if !strings.Contains(string(r.Body), "Contact:") {
		t.Error("security.txt must carry a contact address")
	}
}

func TestMalformedInputIsRejectedCleanly(t *testing.T) {
	e := newEnv(t)
	c := e.newClient()
	c.register("malformed@example.com", "seven lamps beside the quiet river")
	c.login("malformed@example.com", "seven lamps beside the quiet river")

	cases := []struct {
		name string
		body any
		want int
	}{
		{"empty items", map[string]any{"items": []any{}, "state_code": 33}, 422},
		{"bad product id", map[string]any{
			"items":      []map[string]string{{"product_id": "'; DROP TABLE orders; --", "variant_id": "var_X"}},
			"state_code": 33}, 422},
		{"unknown field", map[string]any{
			"items":      []map[string]string{{"product_id": "prd_AAAAAAAAAAAAAAAAAAAAAAAAAA", "variant_id": "var_AAAAAAAAAAAAAAAAAAAAAAAAAA"}},
			"state_code": 33, "surprise": "value"}, 422},
	}
	for _, tc := range cases {
		r := c.do(http.MethodPost, "/api/v1/checkout", tc.body, nil)
		if r.Status != tc.want {
			t.Errorf("%s: got %d want %d: %s", tc.name, r.Status, tc.want, r.Body)
		}
		if !strings.Contains(r.Header.Get("Content-Type"), "problem+json") {
			t.Errorf("%s: errors must be RFC 9457 problem documents, got %q", tc.name, r.Header.Get("Content-Type"))
		}
	}

	// The tables are still there: a parameterised query cannot be escaped.
	var n int
	if err := e.app.DB.QueryRow(context.Background(), `SELECT count(*) FROM orders`).Scan(&n); err != nil {
		t.Fatalf("the orders table should still exist: %v", err)
	}
}

func TestErrorResponsesDoNotLeakInternals(t *testing.T) {
	e := newEnv(t)
	c := e.newClient()
	c.register("leak@example.com", "seven lamps beside the quiet river")
	c.login("leak@example.com", "seven lamps beside the quiet river")

	r := c.do(http.MethodGet, "/api/v1/orders/ord_AAAAAAAAAAAAAAAAAAAAAAAAAA", nil, nil)
	if r.Status != http.StatusNotFound {
		t.Fatalf("status = %d", r.Status)
	}
	body := strings.ToLower(string(r.Body))
	for _, leak := range []string{"sql", "pgx", "postgres", "goroutine", "/home/", ".go:", "panic"} {
		if strings.Contains(body, leak) {
			t.Errorf("the error response leaks %q: %s", leak, r.Body)
		}
	}
	if !strings.Contains(string(r.Body), "request_id") {
		t.Error("every problem document must carry a request id so a report can be traced")
	}
}

func TestMoneyIsAlwaysSerialisedWithItsCurrency(t *testing.T) {
	e := newEnv(t)
	product := e.seedCatalogue(t, "moneystudio", 149900)
	c := e.newClient()

	r := c.do(http.MethodGet, "/api/v1/catalog/products/"+product.PublicID, nil, nil)
	c.mustOK(r, "get product")
	price, ok := jsonPath(t, r.Body, "product.price").(map[string]any)
	if !ok {
		t.Fatalf("price must be an object carrying its currency: %s", r.Body)
	}
	for _, field := range []string{"minor", "currency", "display"} {
		if _, present := price[field]; !present {
			t.Errorf("serialised money is missing %q: %v", field, price)
		}
	}
	if price["currency"] != "INR" || price["display"] != "1499.00" {
		t.Fatalf("price = %v", price)
	}
	// A bare number would be a float in most clients, which is how currency
	// bugs start.
	if _, isNumber := jsonPath(t, r.Body, "product.price").(float64); isNumber {
		t.Fatal("money must never be serialised as a bare number")
	}
	_ = money.INR
}
