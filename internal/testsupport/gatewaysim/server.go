// Package gatewaysim is a local server that speaks the Razorpay HTTP wire
// protocol: the same paths, the same JSON shapes, the same HMAC-SHA256
// signature schemes.
//
// It exists so the end-to-end suite exercises the REAL payment adapter,
// including real signature verification, real idempotency handling and real
// error classification. Nothing in internal/ knows this binary exists, and no
// production code path can reach it: it is a test double at the network
// boundary, which is the only honest place to put one when the counterparty is
// a third-party API you cannot call from CI.
//
// What it deliberately does NOT simulate, and what therefore still has to be
// exercised against the provider's own sandbox before go-live:
//   - real linked-account KYC activation and the holds that follow from it,
//   - real bank settlement timing and UTR issuance,
//   - the provider's own rate limits and outage behaviour.
//
// These limits are restated in docs/runbooks/go-live-checklist.md.
package gatewaysim

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config configures a simulator instance.
type Config struct {
	KeyID         string
	KeySecret     string
	WebhookSecret string
	// Latency injects artificial per-call delay, for load testing.
	Latency time.Duration
}

// DefaultConfig returns credentials that are obviously simulated, so a real
// key can never be mistaken for one of these in a log or a config file.
func DefaultConfig() Config {
	return Config{
		KeyID:         "rzp_test_simulated",
		KeySecret:     "simulated_key_secret",
		WebhookSecret: "simulated_webhook_secret",
	}
}

// New returns an http.Handler implementing the provider protocol.
func New(cfg Config) http.Handler {
	st := &state{
		orders: map[string]*order{}, payments: map[string]*payment{},
		transfers: map[string]*transfer{}, accounts: map[string]*account{},
		refunds: map[string]map[string]any{}, idempotency: map[string]json.RawMessage{},
		failNext: map[string]int{}, latency: cfg.Latency,
	}
	return newServer(st, cfg.KeyID, cfg.KeySecret, cfg.WebhookSecret)
}

type order struct {
	ID        string           `json:"id"`
	Amount    int64            `json:"amount"`
	Currency  string           `json:"currency"`
	Receipt   string           `json:"receipt"`
	Status    string           `json:"status"`
	CreatedAt int64            `json:"created_at"`
	Transfers []map[string]any `json:"-"`
	Notes     map[string]any   `json:"notes"`
}

type payment struct {
	ID            string         `json:"id"`
	OrderID       string         `json:"order_id"`
	Amount        int64          `json:"amount"`
	Currency      string         `json:"currency"`
	Status        string         `json:"status"`
	Method        string         `json:"method"`
	International bool           `json:"international"`
	Fee           *int64         `json:"fee"`
	Tax           *int64         `json:"tax"`
	CreatedAt     int64          `json:"created_at"`
	Captured      bool           `json:"captured"`
	Notes         map[string]any `json:"notes"`
	Card          *cardInfo      `json:"card,omitempty"`
	Refunded      int64          `json:"-"`
}

type cardInfo struct {
	Network string `json:"network"`
}

type transfer struct {
	ID             string         `json:"id"`
	Recipient      string         `json:"recipient"`
	Amount         int64          `json:"amount"`
	Currency       string         `json:"currency"`
	Status         string         `json:"status"`
	OnHold         bool           `json:"on_hold"`
	OnHoldUntil    *int64         `json:"on_hold_until"`
	AmountReversed int64          `json:"amount_reversed"`
	PaymentID      string         `json:"source"`
	Notes          map[string]any `json:"notes"`
}

type account struct {
	ID           string              `json:"id"`
	Status       string              `json:"status"`
	ActivatedAt  *int64              `json:"activated_at"`
	Email        string              `json:"email"`
	ReferenceID  string              `json:"reference_id"`
	Requirements []map[string]string `json:"requirements"`
}

type state struct {
	mu          sync.Mutex
	orders      map[string]*order
	payments    map[string]*payment
	transfers   map[string]*transfer
	accounts    map[string]*account
	refunds     map[string]map[string]any
	idempotency map[string]json.RawMessage
	seq         int64
	// failNext lets a test force a provider-side failure for one call.
	failNext map[string]int
	// latency injects artificial delay for load testing.
	latency time.Duration
}

func (s *state) nextID(prefix string) string {
	s.seq++
	return fmt.Sprintf("%s_SIM%012d", prefix, s.seq)
}

type server struct {
	st            *state
	keyID         string
	keySecret     string
	webhookSecret string
	mux           *http.ServeMux
}

func newServer(st *state, keyID, keySecret, webhookSecret string) *server {
	s := &server{st: st, keyID: keyID, keySecret: keySecret, webhookSecret: webhookSecret, mux: http.NewServeMux()}

	s.mux.HandleFunc("POST /v1/orders", s.auth(s.createOrder))
	s.mux.HandleFunc("GET /v1/payments/{id}", s.auth(s.getPayment))
	s.mux.HandleFunc("POST /v1/payments/{id}/capture", s.auth(s.capturePayment))
	s.mux.HandleFunc("POST /v1/payments/{id}/transfers", s.auth(s.createTransfer))
	s.mux.HandleFunc("POST /v1/payments/{id}/refund", s.auth(s.refundPayment))
	s.mux.HandleFunc("GET /v1/transfers/{id}", s.auth(s.getTransfer))
	s.mux.HandleFunc("PATCH /v1/transfers/{id}", s.auth(s.patchTransfer))
	s.mux.HandleFunc("POST /v1/transfers/{id}/reversals", s.auth(s.reverseTransfer))
	s.mux.HandleFunc("POST /v2/accounts", s.auth(s.createAccount))
	s.mux.HandleFunc("GET /v2/accounts/{id}", s.auth(s.getAccount))
	s.mux.HandleFunc("POST /v1/fund_accounts/validations", s.auth(s.validateFundAccount))

	// Control plane. These paths do not exist at the real provider; they are
	// how a test plays the part of the customer, the bank or the network.
	s.mux.HandleFunc("POST /_sim/pay", s.simPay)
	s.mux.HandleFunc("POST /_sim/activate", s.simActivate)
	s.mux.HandleFunc("POST /_sim/webhook", s.simWebhook)
	s.mux.HandleFunc("POST /_sim/fail-next", s.simFailNext)
	s.mux.HandleFunc("GET /_sim/state", s.simState)
	s.mux.HandleFunc("GET /_sim/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.st.latency > 0 {
		time.Sleep(s.st.latency)
	}
	s.mux.ServeHTTP(w, r)
}

func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != s.keyID || pass != s.keySecret {
			writeErr(w, 401, "BAD_REQUEST_ERROR", "Authentication failed")
			return
		}
		if key := r.Header.Get("Idempotency-Key"); key != "" {
			s.st.mu.Lock()
			cached, hit := s.st.idempotency[r.Method+" "+r.URL.Path+" "+key]
			s.st.mu.Unlock()
			if hit {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Sim-Idempotent-Replay", "true")
				w.WriteHeader(200)
				_, _ = w.Write(cached)
				return
			}
			rec := &recordingWriter{ResponseWriter: w, buf: &bytes.Buffer{}, status: 200}
			next(rec, r)
			if rec.status >= 200 && rec.status < 300 {
				s.st.mu.Lock()
				s.st.idempotency[r.Method+" "+r.URL.Path+" "+key] = rec.buf.Bytes()
				s.st.mu.Unlock()
			}
			return
		}
		next(w, r)
	}
}

type recordingWriter struct {
	http.ResponseWriter
	buf    *bytes.Buffer
	status int
}

func (w *recordingWriter) WriteHeader(c int) { w.status = c; w.ResponseWriter.WriteHeader(c) }
func (w *recordingWriter) Write(b []byte) (int, error) {
	w.buf.Write(b)
	return w.ResponseWriter.Write(b)
}

func (s *server) shouldFail(op string) bool {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if n := s.st.failNext[op]; n > 0 {
		s.st.failNext[op] = n - 1
		return true
	}
	return false
}

// ---- provider endpoints -----------------------------------------------------

func (s *server) createOrder(w http.ResponseWriter, r *http.Request) {
	if s.shouldFail("create_order") {
		writeErr(w, 503, "SERVER_ERROR", "simulated provider outage")
		return
	}
	var in struct {
		Amount    int64            `json:"amount"`
		Currency  string           `json:"currency"`
		Receipt   string           `json:"receipt"`
		Transfers []map[string]any `json:"transfers"`
		Notes     map[string]any   `json:"notes"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Amount <= 0 {
		writeErr(w, 400, "BAD_REQUEST_ERROR", "amount must be at least 100")
		return
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()

	var total int64
	for _, t := range in.Transfers {
		acct, _ := t["account"].(string)
		if _, ok := s.st.accounts[acct]; !ok {
			writeErr(w, 400, "BAD_REQUEST_ERROR", "The account id provided does not exist: "+acct)
			return
		}
		total += toInt64(t["amount"])
	}
	if total > in.Amount {
		writeErr(w, 400, "BAD_REQUEST_ERROR", "Total transfer amount exceeds the payment amount")
		return
	}

	o := &order{
		ID: s.st.nextID("order"), Amount: in.Amount, Currency: strings.ToUpper(in.Currency),
		Receipt: in.Receipt, Status: "created", CreatedAt: time.Now().Unix(),
		Transfers: in.Transfers, Notes: in.Notes,
	}
	s.st.orders[o.ID] = o
	writeJSON(w, 200, o)
}

func (s *server) getPayment(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	p, ok := s.st.payments[r.PathValue("id")]
	if !ok {
		writeErr(w, 404, "BAD_REQUEST_ERROR", "The id provided does not exist")
		return
	}
	writeJSON(w, 200, p)
}

func (s *server) capturePayment(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Amount   int64  `json:"amount"`
		Currency string `json:"currency"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	p, ok := s.st.payments[r.PathValue("id")]
	if !ok {
		writeErr(w, 404, "BAD_REQUEST_ERROR", "The id provided does not exist")
		return
	}
	if p.Status == "captured" {
		writeJSON(w, 200, p) // capture is idempotent at the provider too
		return
	}
	if p.Status != "authorized" {
		writeErr(w, 400, "BAD_REQUEST_ERROR", "Payment is not authorized and cannot be captured")
		return
	}
	if in.Amount != p.Amount {
		writeErr(w, 400, "BAD_REQUEST_ERROR", "Capture amount must equal the authorized amount")
		return
	}
	p.Status = "captured"
	p.Captured = true
	// A realistic fee: 2% plus 18% GST on that fee.
	fee := p.Amount * 200 / 10000
	tax := fee * 1800 / 10000
	p.Fee, p.Tax = &fee, &tax
	writeJSON(w, 200, p)
}

func (s *server) createTransfer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Account     string         `json:"account"`
		Amount      int64          `json:"amount"`
		Currency    string         `json:"currency"`
		OnHold      any            `json:"on_hold"`
		OnHoldUntil int64          `json:"on_hold_until"`
		Notes       map[string]any `json:"notes"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	p, ok := s.st.payments[r.PathValue("id")]
	if !ok {
		writeErr(w, 404, "BAD_REQUEST_ERROR", "The payment id provided does not exist")
		return
	}
	acct, ok := s.st.accounts[in.Account]
	if !ok {
		writeErr(w, 400, "BAD_REQUEST_ERROR", "The account id provided does not exist")
		return
	}
	// The real trap this reproduces: a linked account whose KYC is not
	// activated cannot receive a transfer.
	if acct.Status != "activated" {
		writeErr(w, 400, "BAD_REQUEST_ERROR",
			"The linked account is not activated. Transfers to this account are not permitted until KYC is complete.")
		return
	}
	var allocated int64
	for _, t := range s.st.transfers {
		if t.PaymentID == p.ID {
			allocated += t.Amount
		}
	}
	if allocated+in.Amount > p.Amount {
		writeErr(w, 400, "BAD_REQUEST_ERROR", "Total transfer amount exceeds the payment amount")
		return
	}

	t := &transfer{
		ID: s.st.nextID("trf"), Recipient: in.Account, Amount: in.Amount,
		Currency: strings.ToUpper(in.Currency), Status: "processed",
		PaymentID: p.ID, Notes: in.Notes,
	}
	if truthy(in.OnHold) {
		t.OnHold = true
		t.Status = "pending"
		if in.OnHoldUntil > 0 {
			v := in.OnHoldUntil
			t.OnHoldUntil = &v
		}
	}
	s.st.transfers[t.ID] = t
	writeJSON(w, 200, t)
}

func (s *server) getTransfer(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	t, ok := s.st.transfers[r.PathValue("id")]
	if !ok {
		writeErr(w, 404, "BAD_REQUEST_ERROR", "The id provided does not exist")
		return
	}
	writeJSON(w, 200, t)
}

func (s *server) patchTransfer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OnHold      any   `json:"on_hold"`
		OnHoldUntil int64 `json:"on_hold_until"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	t, ok := s.st.transfers[r.PathValue("id")]
	if !ok {
		writeErr(w, 404, "BAD_REQUEST_ERROR", "The id provided does not exist")
		return
	}
	if truthy(in.OnHold) {
		t.OnHold, t.Status = true, "pending"
		if in.OnHoldUntil > 0 {
			v := in.OnHoldUntil
			t.OnHoldUntil = &v
		}
	} else {
		t.OnHold, t.Status, t.OnHoldUntil = false, "processed", nil
	}
	writeJSON(w, 200, t)
}

func (s *server) reverseTransfer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Amount int64 `json:"amount"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	t, ok := s.st.transfers[r.PathValue("id")]
	if !ok {
		writeErr(w, 404, "BAD_REQUEST_ERROR", "The id provided does not exist")
		return
	}
	if t.AmountReversed+in.Amount > t.Amount {
		writeErr(w, 400, "BAD_REQUEST_ERROR", "Reversal amount exceeds the transferred amount")
		return
	}
	t.AmountReversed += in.Amount
	if t.AmountReversed == t.Amount {
		t.Status = "reversed"
	}
	writeJSON(w, 200, map[string]any{
		"id": s.st.nextID("rvrsl"), "amount": in.Amount, "currency": t.Currency, "transfer_id": t.ID,
	})
}

func (s *server) refundPayment(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Amount     int64          `json:"amount"`
		ReverseAll any            `json:"reverse_all"`
		Notes      map[string]any `json:"notes"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	p, ok := s.st.payments[r.PathValue("id")]
	if !ok {
		writeErr(w, 404, "BAD_REQUEST_ERROR", "The id provided does not exist")
		return
	}
	if p.Status != "captured" && p.Status != "refunded" {
		writeErr(w, 400, "BAD_REQUEST_ERROR", "Only captured payments can be refunded")
		return
	}
	if p.Refunded+in.Amount > p.Amount {
		writeErr(w, 400, "BAD_REQUEST_ERROR", "The refund amount exceeds the amount refundable")
		return
	}
	p.Refunded += in.Amount
	if p.Refunded == p.Amount {
		p.Status = "refunded"
	}
	if truthy(in.ReverseAll) {
		for _, t := range s.st.transfers {
			if t.PaymentID == p.ID && t.AmountReversed < t.Amount {
				t.AmountReversed = t.Amount
				t.Status = "reversed"
			}
		}
	}
	ref := map[string]any{
		"id": s.st.nextID("rfnd"), "amount": in.Amount, "currency": p.Currency,
		"payment_id": p.ID, "status": "processed", "notes": in.Notes,
	}
	s.st.refunds[ref["id"].(string)] = ref
	writeJSON(w, 200, ref)
}

func (s *server) createAccount(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email       string `json:"email"`
		ReferenceID string `json:"reference_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	a := &account{
		ID: s.st.nextID("acc"), Status: "created", Email: in.Email, ReferenceID: in.ReferenceID,
		Requirements: []map[string]string{{"field_reference": "individual_proof_of_address", "status": "required"}},
	}
	s.st.accounts[a.ID] = a
	writeJSON(w, 200, a)
}

func (s *server) getAccount(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	a, ok := s.st.accounts[r.PathValue("id")]
	if !ok {
		writeErr(w, 404, "BAD_REQUEST_ERROR", "The id provided does not exist")
		return
	}
	writeJSON(w, 200, a)
}

func (s *server) validateFundAccount(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Account struct {
			AccountType string `json:"account_type"`
			BankAccount struct {
				Name          string `json:"name"`
				IFSC          string `json:"ifsc"`
				AccountNumber string `json:"account_number"`
			} `json:"bank_account"`
		} `json:"account"`
	}
	if !decode(w, r, &in) {
		return
	}
	// A deterministic rule a test can rely on: accounts ending 0000 are closed.
	acctStatus := "active"
	if strings.HasSuffix(in.Account.BankAccount.AccountNumber, "0000") {
		acctStatus = "invalid"
	}
	s.st.mu.Lock()
	id := s.st.nextID("fav")
	s.st.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"id": id, "status": "completed",
		"results": map[string]any{
			"account_status":  acctStatus,
			"registered_name": in.Account.BankAccount.Name,
		},
	})
}

// ---- control plane ----------------------------------------------------------

// simPay plays the customer: it authorises (and optionally captures) a payment
// against an order and returns the checkout signature the browser would post
// back, computed exactly as the provider computes it.
func (s *server) simPay(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OrderID       string `json:"order_id"`
		Method        string `json:"method"`
		Capture       bool   `json:"capture"`
		Fail          bool   `json:"fail"`
		International bool   `json:"international"`
		Network       string `json:"network"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.st.mu.Lock()
	o, ok := s.st.orders[in.OrderID]
	if !ok {
		s.st.mu.Unlock()
		writeErr(w, 404, "BAD_REQUEST_ERROR", "order not found")
		return
	}
	p := &payment{
		ID: s.st.nextID("pay"), OrderID: o.ID, Amount: o.Amount, Currency: o.Currency,
		Status: "authorized", Method: defaultStr(in.Method, "upi"), CreatedAt: time.Now().Unix(),
		International: in.International,
	}
	if in.Network != "" {
		p.Card = &cardInfo{Network: in.Network}
	}
	if in.Fail {
		p.Status = "failed"
	} else if in.Capture {
		p.Status = "captured"
		p.Captured = true
		fee := p.Amount * 200 / 10000
		tax := fee * 1800 / 10000
		p.Fee, p.Tax = &fee, &tax
		o.Status = "paid"
		// Apply the split instruction that was attached to the order.
		for _, t := range o.Transfers {
			acct, _ := t["account"].(string)
			tr := &transfer{
				ID: s.st.nextID("trf"), Recipient: acct, Amount: toInt64(t["amount"]),
				Currency: o.Currency, Status: "processed", PaymentID: p.ID,
			}
			if truthy(t["on_hold"]) {
				tr.OnHold, tr.Status = true, "pending"
				if v := toInt64(t["on_hold_until"]); v > 0 {
					tr.OnHoldUntil = &v
				}
			}
			s.st.transfers[tr.ID] = tr
		}
	}
	s.st.payments[p.ID] = p
	s.st.mu.Unlock()

	sig := hmacHex(s.keySecret, o.ID+"|"+p.ID)
	writeJSON(w, 200, map[string]any{
		"razorpay_order_id":   o.ID,
		"razorpay_payment_id": p.ID,
		"razorpay_signature":  sig,
		"status":              p.Status,
	})
}

func (s *server) simActivate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AccountID string `json:"account_id"`
		Status    string `json:"status"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	a, ok := s.st.accounts[in.AccountID]
	if !ok {
		writeErr(w, 404, "BAD_REQUEST_ERROR", "account not found")
		return
	}
	a.Status = defaultStr(in.Status, "activated")
	if a.Status == "activated" {
		now := time.Now().Unix()
		a.ActivatedAt = &now
		a.Requirements = nil
	}
	writeJSON(w, 200, a)
}

// simWebhook signs an arbitrary payload with the webhook secret and POSTs it to
// the target, exactly as the provider would.
func (s *server) simWebhook(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TargetURL string         `json:"target_url"`
		Event     string         `json:"event"`
		EventID   string         `json:"event_id"`
		Payload   map[string]any `json:"payload"`
		// BadSignature lets a test assert that a forged webhook is refused.
		BadSignature bool `json:"bad_signature"`
	}
	if !decode(w, r, &in) {
		return
	}
	body, err := json.Marshal(map[string]any{
		"entity": "event", "account_id": "acc_sim", "event": in.Event,
		"contains": keysOf(in.Payload), "created_at": time.Now().Unix(),
		"payload": in.Payload,
	})
	if err != nil {
		writeErr(w, 500, "SERVER_ERROR", err.Error())
		return
	}
	sig := hmacHex(s.webhookSecret, string(body))
	if in.BadSignature {
		sig = hmacHex("the-wrong-secret", string(body))
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, in.TargetURL, bytes.NewReader(body))
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST_ERROR", err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)
	if in.EventID != "" {
		req.Header.Set("X-Razorpay-Event-Id", in.EventID)
	}
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		writeErr(w, 502, "GATEWAY_ERROR", err.Error())
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	writeJSON(w, 200, map[string]any{
		"delivered_status": resp.StatusCode,
		"response":         string(respBody),
		"signature":        sig,
	})
}

func (s *server) simFailNext(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Op    string `json:"op"`
		Times int    `json:"times"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Times <= 0 {
		in.Times = 1
	}
	s.st.mu.Lock()
	s.st.failNext[in.Op] = in.Times
	s.st.mu.Unlock()
	writeJSON(w, 200, map[string]any{"op": in.Op, "times": in.Times})
}

func (s *server) simState(w http.ResponseWriter, _ *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"orders": len(s.st.orders), "payments": len(s.st.payments),
		"transfers": len(s.st.transfers), "accounts": len(s.st.accounts),
		"refunds": len(s.st.refunds),
	})
}

// ---- helpers ----------------------------------------------------------------

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST_ERROR", "could not read body")
		return false
	}
	if len(body) == 0 {
		return true
	}
	if err := json.Unmarshal(body, dst); err != nil {
		writeErr(w, 400, "BAD_REQUEST_ERROR", "malformed JSON: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "description": desc, "source": "gatewaysim", "step": "sim"},
	})
}

func hmacHex(secret, payload string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	}
	return 0
}

func truthy(v any) bool {
	switch n := v.(type) {
	case bool:
		return n
	case float64:
		return n != 0
	case int:
		return n != 0
	case string:
		return n == "1" || strings.EqualFold(n, "true")
	}
	return false
}

func defaultStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
