// Command loadgen drives the marketplace under sustained concurrent load and
// then verifies that the books still balance.
//
// A load test that only reports latency is half a test. The interesting
// question for a payments system is not "how fast" but "does it stay correct
// while it is fast": under contention, do two buyers both get the last
// limited-edition copy, does a retried checkout charge twice, does the ledger
// still net to zero. So this harness runs a realistic mixed workload and then
// asserts the invariants, and it exits non-zero if any of them broke.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type options struct {
	baseURL      string
	gatewayURL   string
	workers      int
	duration     time.Duration
	rampUp       time.Duration
	scenario     string
	metricsToken string
	verifyURL    string
	thinkTime    time.Duration
	timeout      time.Duration
	// distinctClients makes each virtual user present a unique address via
	// X-Forwarded-For. Without it every worker shares one per-IP rate-limit
	// bucket and the run measures the rate limiter rather than the
	// application. It requires the server to trust this host as a proxy.
	distinctClients bool
}

func main() {
	var o options
	flag.StringVar(&o.baseURL, "url", "http://127.0.0.1:8080", "base URL of the application under test")
	flag.StringVar(&o.gatewayURL, "gateway", "", "base URL of the payment gateway simulator (required for purchase scenarios)")
	flag.IntVar(&o.workers, "workers", 32, "concurrent virtual users")
	flag.DurationVar(&o.duration, "duration", 30*time.Second, "how long to sustain load")
	flag.DurationVar(&o.rampUp, "ramp", 3*time.Second, "time to bring all workers online")
	flag.StringVar(&o.scenario, "scenario", "mixed", "browse | purchase | mixed | auth")
	flag.StringVar(&o.metricsToken, "metrics-token", "", "bearer token for the metrics endpoint")
	flag.StringVar(&o.verifyURL, "verify-url", "", "base URL used for invariant checks (defaults to -url)")
	flag.DurationVar(&o.thinkTime, "think", 0, "pause between a virtual user's requests")
	flag.DurationVar(&o.timeout, "timeout", 20*time.Second, "per-request timeout")
	flag.BoolVar(&o.distinctClients, "distinct-clients", true,
		"present each virtual user as a distinct client address (requires the server to trust this host as a proxy)")
	flag.Parse()

	if o.verifyURL == "" {
		o.verifyURL = o.baseURL
	}
	if (o.scenario == "purchase" || o.scenario == "mixed") && o.gatewayURL == "" {
		fmt.Fprintln(os.Stderr, "loadgen: -gateway is required for the purchase and mixed scenarios")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	report, err := run(ctx, o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loadgen:", err)
		os.Exit(1)
	}
	report.print(o)

	if report.failed() {
		os.Exit(1)
	}
}

// ---- measurement ------------------------------------------------------------

// collector accumulates latency samples per operation.
//
// Samples are kept in full rather than bucketed, because a load test that
// reports an approximate p99 is reporting the number people actually care about
// with the least precision.
type collector struct {
	mu       sync.Mutex
	samples  map[string][]time.Duration
	ok       map[string]int64
	errs     map[string]int64
	status   map[int]int64
	firstErr map[string]string
}

func newCollector() *collector {
	return &collector{
		samples: map[string][]time.Duration{},
		ok:      map[string]int64{}, errs: map[string]int64{},
		status: map[int]int64{}, firstErr: map[string]string{},
	}
}

func (c *collector) record(op string, d time.Duration, status int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.samples[op] = append(c.samples[op], d)
	c.status[status]++
	if err != nil || status >= 500 || status == 0 {
		c.errs[op]++
		if _, seen := c.firstErr[op]; !seen {
			msg := fmt.Sprintf("HTTP %d", status)
			if err != nil {
				msg = err.Error()
			}
			c.firstErr[op] = msg
		}
		return
	}
	c.ok[op]++
}

type opStats struct {
	Op     string
	Count  int
	OK     int64
	Errors int64
	Min    time.Duration
	P50    time.Duration
	P90    time.Duration
	P95    time.Duration
	P99    time.Duration
	Max    time.Duration
	Mean   time.Duration
}

func (c *collector) stats() []opStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]opStats, 0, len(c.samples))
	for op, s := range c.samples {
		if len(s) == 0 {
			continue
		}
		sorted := append([]time.Duration(nil), s...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		var total time.Duration
		for _, d := range sorted {
			total += d
		}
		out = append(out, opStats{
			Op: op, Count: len(sorted), OK: c.ok[op], Errors: c.errs[op],
			Min: sorted[0], Max: sorted[len(sorted)-1],
			P50: percentile(sorted, 50), P90: percentile(sorted, 90),
			P95: percentile(sorted, 95), P99: percentile(sorted, 99),
			Mean: total / time.Duration(len(sorted)),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Op < out[j].Op })
	return out
}

// percentile uses nearest-rank, which is unambiguous and does not invent a
// value that never occurred.
func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(float64(p)/100*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

// ---- report -----------------------------------------------------------------

type report struct {
	Stats      []opStats
	Statuses   map[int]int64
	FirstError map[string]string
	Elapsed    time.Duration
	Requests   int64
	Errors     int64
	Invariants []invariant
	Purchases  int64
}

type invariant struct {
	Name   string
	Passed bool
	Detail string
}

func (r *report) failed() bool {
	for _, inv := range r.Invariants {
		if !inv.Passed {
			return true
		}
	}
	// A sustained error rate above 1% is a failed run, not a slow one.
	if r.Requests > 0 && float64(r.Errors)/float64(r.Requests) > 0.01 {
		return true
	}
	return false
}

func (r *report) print(o options) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 78))
	fmt.Printf("LOAD TEST: scenario=%s workers=%d duration=%s\n", o.scenario, o.workers, o.duration)
	fmt.Printf("%s\n\n", strings.Repeat("=", 78))

	fmt.Printf("%-34s %8s %8s %8s %8s %8s %8s\n", "operation", "count", "p50", "p90", "p95", "p99", "max")
	fmt.Printf("%s\n", strings.Repeat("-", 78))
	for _, s := range r.Stats {
		fmt.Printf("%-34s %8d %8s %8s %8s %8s %8s\n", s.Op, s.Count,
			ms(s.P50), ms(s.P90), ms(s.P95), ms(s.P99), ms(s.Max))
	}

	fmt.Printf("\nthroughput: %.1f requests/second over %s\n",
		float64(r.Requests)/r.Elapsed.Seconds(), r.Elapsed.Round(time.Millisecond))
	if r.Purchases > 0 {
		fmt.Printf("completed purchases: %d (%.1f/second)\n",
			r.Purchases, float64(r.Purchases)/r.Elapsed.Seconds())
	}
	errRate := 0.0
	if r.Requests > 0 {
		errRate = float64(r.Errors) / float64(r.Requests) * 100
	}
	fmt.Printf("errors: %d of %d (%.3f%%)\n", r.Errors, r.Requests, errRate)

	fmt.Printf("\nstatus codes: ")
	codes := make([]int, 0, len(r.Statuses))
	for c := range r.Statuses {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	for _, c := range codes {
		fmt.Printf("%d=%d  ", c, r.Statuses[c])
	}
	fmt.Println()

	if len(r.FirstError) > 0 {
		fmt.Printf("\nfirst error per operation:\n")
		for op, msg := range r.FirstError {
			fmt.Printf("  %-32s %s\n", op, truncate(msg, 120))
		}
	}

	fmt.Printf("\n%s\nCORRECTNESS UNDER LOAD\n%s\n", strings.Repeat("-", 78), strings.Repeat("-", 78))
	for _, inv := range r.Invariants {
		mark := "PASS"
		if !inv.Passed {
			mark = "FAIL"
		}
		fmt.Printf("  [%s] %-44s %s\n", mark, inv.Name, inv.Detail)
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 78))
	if r.failed() {
		fmt.Println("RESULT: FAILED")
	} else {
		fmt.Println("RESULT: PASSED")
	}
	fmt.Printf("%s\n\n", strings.Repeat("=", 78))
}

func ms(d time.Duration) string {
	return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---- driver -----------------------------------------------------------------

func run(ctx context.Context, o options) (*report, error) {
	c := newCollector()
	var requests, purchases atomic.Int64

	catalogue, err := fetchCatalogue(ctx, o)
	if err != nil {
		return nil, err
	}
	if len(catalogue) == 0 && o.scenario != "auth" {
		return nil, fmt.Errorf("the catalogue is empty; seed it before running a purchase or browse scenario")
	}

	deadline := time.Now().Add(o.duration)
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < o.workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Ramp up so the run measures steady state rather than a thundering
			// herd at t=0.
			if o.rampUp > 0 {
				delay := time.Duration(int64(o.rampUp) * int64(id) / int64(o.workers))
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
			}
			vu := newVirtualUser(id, o, c, catalogue)
			for time.Now().Before(deadline) {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if vu.iterate(ctx) {
					purchases.Add(1)
				}
				requests.Add(vu.takeRequestCount())
				if o.thinkTime > 0 {
					time.Sleep(o.thinkTime)
				}
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	stats := c.stats()
	var totalReq, totalErr int64
	for _, s := range stats {
		totalReq += int64(s.Count)
		totalErr += s.Errors
	}

	rep := &report{
		Stats: stats, Statuses: c.status, FirstError: c.firstErr,
		Elapsed: elapsed, Requests: totalReq, Errors: totalErr,
		Purchases: purchases.Load(),
	}
	rep.Invariants = checkInvariants(context.WithoutCancel(ctx), o)
	return rep, nil
}

type product struct {
	ID      string `json:"id"`
	Variant string `json:"-"`
}

func fetchCatalogue(ctx context.Context, o options) ([]product, error) {
	hc := &http.Client{Timeout: o.timeout}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, o.baseURL+"/api/v1/catalog/products?limit=60", nil)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach the application at %s: %w", o.baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalogue returned HTTP %d", resp.StatusCode)
	}
	var body struct {
		Products []struct {
			ID string `json:"id"`
		} `json:"products"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	out := make([]product, 0, len(body.Products))
	for _, p := range body.Products {
		vreq, _ := http.NewRequestWithContext(ctx, http.MethodGet, o.baseURL+"/api/v1/catalog/products/"+p.ID, nil)
		vresp, err := hc.Do(vreq)
		if err != nil {
			continue
		}
		var detail struct {
			Variants []struct {
				ID string `json:"id"`
			} `json:"variants"`
		}
		_ = json.NewDecoder(vresp.Body).Decode(&detail)
		vresp.Body.Close()
		if len(detail.Variants) > 0 {
			out = append(out, product{ID: p.ID, Variant: detail.Variants[0].ID})
		}
	}
	return out, nil
}

// ---- invariants -------------------------------------------------------------

// checkInvariants asks the application, after the load, whether it is still
// correct. These are the assertions that make this a correctness test rather
// than a benchmark.
func checkInvariants(ctx context.Context, o options) []invariant {
	hc := &http.Client{Timeout: 30 * time.Second}
	var out []invariant

	get := func(path string) (int, []byte) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.verifyURL+path, nil)
		if err != nil {
			return 0, nil
		}
		if o.metricsToken != "" {
			req.Header.Set("Authorization", "Bearer "+o.metricsToken)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return 0, []byte(err.Error())
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, body
	}

	status, body := get("/internal/verify/trial-balance")
	switch {
	case status == http.StatusOK && bytes.Contains(body, []byte(`"balanced":true`)):
		out = append(out, invariant{"double-entry ledger balances", true,
			"debits equal credits in every currency"})
	case status == 0:
		out = append(out, invariant{"double-entry ledger balances", false,
			"could not reach the verification endpoint: " + truncate(string(body), 80)})
	default:
		out = append(out, invariant{"double-entry ledger balances", false,
			fmt.Sprintf("HTTP %d: %s", status, truncate(string(body), 140))})
	}

	status, body = get("/internal/verify/audit-chain")
	if status == http.StatusOK && bytes.Contains(body, []byte(`"intact":true`)) {
		out = append(out, invariant{"audit log chain intact", true, "no tampering detected"})
	} else {
		out = append(out, invariant{"audit log chain intact", false,
			fmt.Sprintf("HTTP %d: %s", status, truncate(string(body), 140))})
	}

	status, body = get("/internal/verify/consistency")
	if status == http.StatusOK && bytes.Contains(body, []byte(`"consistent":true`)) {
		out = append(out, invariant{"orders reconcile with the ledger", true,
			"every paid order has balanced postings and exactly one licence per item"})
	} else {
		out = append(out, invariant{"orders reconcile with the ledger", false,
			fmt.Sprintf("HTTP %d: %s", status, truncate(string(body), 200))})
	}

	status, _ = get("/readyz")
	out = append(out, invariant{"application still healthy after load",
		status == http.StatusOK, fmt.Sprintf("readiness probe returned HTTP %d", status)})

	return out
}

// ---- virtual user -----------------------------------------------------------

type virtualUser struct {
	id        int
	o         options
	c         *collector
	hc        *http.Client
	gateway   *http.Client
	catalogue []product
	csrf      string
	signedIn  bool
	email     string
	password  string
	requests  int64
	rng       uint64
	clientIP  string
}

func newVirtualUser(id int, o options, c *collector, catalogue []product) *virtualUser {
	jar, _ := cookiejar.New(nil)
	return &virtualUser{
		id: id, o: o, c: c, catalogue: catalogue,
		hc: &http.Client{Jar: jar, Timeout: o.timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		gateway:  &http.Client{Timeout: o.timeout},
		email:    fmt.Sprintf("load-%d-%d@example.com", time.Now().UnixNano(), id),
		password: "seven lamps beside the quiet river",
		rng:      uint64(id)*0x9E3779B97F4A7C15 + 1,
		// A documentation-range address (RFC 5737 TEST-NET-3) per worker, so
		// per-IP limits behave as they would with real, distinct clients.
		clientIP: fmt.Sprintf("203.0.113.%d", 1+id%254),
	}
}

func (v *virtualUser) takeRequestCount() int64 {
	n := v.requests
	v.requests = 0
	return n
}

func (v *virtualUser) next() uint64 {
	v.rng ^= v.rng << 13
	v.rng ^= v.rng >> 7
	v.rng ^= v.rng << 17
	return v.rng
}

// iterate performs one virtual-user cycle and reports whether it completed a
// purchase.
func (v *virtualUser) iterate(ctx context.Context) bool {
	switch v.o.scenario {
	case "browse":
		v.browse(ctx)
		return false
	case "auth":
		v.authCycle(ctx)
		return false
	case "purchase":
		return v.purchase(ctx)
	default: // mixed: a realistic ratio of lookers to buyers
		if v.next()%10 < 7 {
			v.browse(ctx)
			return false
		}
		return v.purchase(ctx)
	}
}

func (v *virtualUser) browse(ctx context.Context) {
	v.call(ctx, "GET", "browse_catalog", "/api/v1/catalog/products?limit=24", nil, nil)
	if len(v.catalogue) > 0 {
		p := v.catalogue[int(v.next()%uint64(len(v.catalogue)))]
		v.call(ctx, "GET", "view_product", "/api/v1/catalog/products/"+p.ID, nil, nil)
	}
	v.call(ctx, "GET", "search", "/api/v1/catalog/search?q=asset+pack", nil, nil)
}

func (v *virtualUser) authCycle(ctx context.Context) {
	v.ensureSession(ctx)
	v.call(ctx, "GET", "session", "/api/v1/auth/session", nil, nil)
}

func (v *virtualUser) purchase(ctx context.Context) bool {
	if !v.ensureSession(ctx) || len(v.catalogue) == 0 {
		return false
	}
	p := v.catalogue[int(v.next()%uint64(len(v.catalogue)))]

	var order struct {
		ID string `json:"id"`
	}
	st, _ := v.call(ctx, "POST", "checkout", "/api/v1/checkout", map[string]any{
		"items":      []map[string]string{{"product_id": p.ID, "variant_id": p.Variant}},
		"state_code": 33, "country": "IN",
	}, &order)
	if st < 200 || st >= 300 || order.ID == "" {
		return false
	}

	var handoff struct {
		IntentID string `json:"intent_id"`
	}
	st, _ = v.call(ctx, "POST", "begin_payment", "/api/v1/orders/"+order.ID+"/payment", nil, &handoff)
	if st < 200 || st >= 300 || handoff.IntentID == "" {
		return false
	}

	// Play the customer at the gateway, exactly as a browser would.
	pay, ok := v.payAtGateway(ctx, handoff.IntentID)
	if !ok {
		return false
	}

	st, _ = v.call(ctx, "POST", "confirm_payment", "/api/v1/orders/"+order.ID+"/confirm", map[string]any{
		"intent_id": pay.OrderID, "payment_id": pay.PaymentID, "signature": pay.Signature,
	}, nil)
	if st < 200 || st >= 300 {
		return false
	}

	v.call(ctx, "GET", "library", "/api/v1/library", nil, nil)
	return true
}

type gatewayPayment struct {
	OrderID   string `json:"razorpay_order_id"`
	PaymentID string `json:"razorpay_payment_id"`
	Signature string `json:"razorpay_signature"`
}

func (v *virtualUser) payAtGateway(ctx context.Context, intentID string) (gatewayPayment, bool) {
	var out gatewayPayment
	buf, _ := json.Marshal(map[string]any{"order_id": intentID, "capture": true, "method": "upi"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.o.gatewayURL+"/_sim/pay", bytes.NewReader(buf))
	if err != nil {
		return out, false
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := v.gateway.Do(req)
	v.requests++
	if err != nil {
		v.c.record("gateway_pay", time.Since(start), 0, err)
		return out, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	v.c.record("gateway_pay", time.Since(start), resp.StatusCode, nil)
	if resp.StatusCode != http.StatusOK {
		return out, false
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, false
	}
	return out, out.PaymentID != ""
}

func (v *virtualUser) ensureSession(ctx context.Context) bool {
	if v.signedIn {
		return true
	}
	v.refreshCSRF(ctx)
	st, _ := v.call(ctx, "POST", "register", "/api/v1/auth/register", map[string]any{
		"email": v.email, "password": v.password, "display_name": "Load User",
		"country": "IN", "state_code": 33, "accept_notice_version": "2026-01-01",
	}, nil)
	if st < 200 || st >= 300 {
		return false
	}
	st, _ = v.call(ctx, "POST", "login", "/api/v1/auth/login", map[string]any{
		"email": v.email, "password": v.password,
	}, nil)
	if st < 200 || st >= 300 {
		return false
	}
	v.refreshCSRF(ctx)
	v.signedIn = true
	return true
}

func (v *virtualUser) refreshCSRF(ctx context.Context) {
	var out struct {
		CSRFToken string `json:"csrf_token"`
	}
	v.call(ctx, "GET", "session", "/api/v1/auth/session", nil, &out)
	if out.CSRFToken != "" {
		v.csrf = out.CSRFToken
	}
}

func (v *virtualUser) call(ctx context.Context, method, op, path string, body, out any) (int, []byte) {
	var reader io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, v.o.baseURL+path, reader)
	if err != nil {
		return 0, nil
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if v.csrf != "" {
		req.Header.Set("X-CSRF-Token", v.csrf)
	}
	req.Header.Set("Origin", v.o.baseURL)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if v.o.distinctClients {
		req.Header.Set("X-Forwarded-For", v.clientIP)
	}

	start := time.Now()
	resp, err := v.hc.Do(req)
	v.requests++
	if err != nil {
		v.c.record(op, time.Since(start), 0, err)
		return 0, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	v.c.record(op, time.Since(start), resp.StatusCode, nil)
	if out != nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, out)
	}
	return resp.StatusCode, raw
}
