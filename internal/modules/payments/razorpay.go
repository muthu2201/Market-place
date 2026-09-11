package payments

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/platform/cryptox"
	"github.com/muthu2201/market-place/internal/platform/metrics"
	"github.com/muthu2201/market-place/internal/platform/money"
)

// Razorpay implements the port against Razorpay, including Route split
// settlement.
//
// Two signature schemes are involved and they use DIFFERENT secrets. Conflating
// them is a real vulnerability, so they are separated here by name and by type:
//
//   - Checkout callback: HMAC-SHA256 of "order_id|payment_id" under the API KEY
//     SECRET, delivered to the browser and posted back by our own page.
//   - Webhook: HMAC-SHA256 of the EXACT raw request body under the WEBHOOK
//     SECRET, delivered server-to-server in X-Razorpay-Signature.
//
// Amounts are exchanged in paise, which is the same integer minor unit this
// system uses internally, so no conversion and therefore no rounding occurs at
// the boundary.
type Razorpay struct {
	c             *client
	keyID         string
	keySecret     string
	webhookSecret string
	// routeMode reports whether this instance may issue split instructions.
	routeMode bool
}

// RazorpayConfig configures the adapter.
type RazorpayConfig struct {
	BaseURL       string
	KeyID         string
	KeySecret     string
	WebhookSecret string
	Timeout       time.Duration
	MaxRetries    int
	RouteMode     bool
	Metrics       *metrics.App
	// AllowPrivateHosts is for tests that point the adapter at a loopback
	// gateway simulator speaking the same wire protocol. Production config
	// rejects a non-https base URL, so this cannot be set from the environment.
	AllowPrivateHosts bool
}

// NewRazorpay builds the adapter, refusing to start without credentials.
func NewRazorpay(cfg RazorpayConfig) (*Razorpay, error) {
	if cfg.KeyID == "" || cfg.KeySecret == "" {
		return nil, fmt.Errorf("payments: razorpay requires a key id and secret")
	}
	if cfg.WebhookSecret == "" {
		return nil, fmt.Errorf("payments: razorpay requires a webhook secret; an unverified webhook is an open door")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.razorpay.com"
	}
	name := "razorpay_bridge"
	if cfg.RouteMode {
		name = "razorpay_route"
	}
	c, err := newClient(clientOptions{
		BaseURL: cfg.BaseURL, Timeout: cfg.Timeout, MaxRetries: cfg.MaxRetries,
		Metrics: cfg.Metrics, Provider: name, AllowPrivateHosts: cfg.AllowPrivateHosts,
	})
	if err != nil {
		return nil, err
	}
	return &Razorpay{
		c: c, keyID: cfg.KeyID, keySecret: cfg.KeySecret,
		webhookSecret: cfg.WebhookSecret, routeMode: cfg.RouteMode,
	}, nil
}

func (r *Razorpay) Name() string {
	if r.routeMode {
		return "razorpay_route"
	}
	return "bridge"
}

func (r *Razorpay) Capabilities() Capabilities {
	return Capabilities{
		SplitSettlement:      r.routeMode,
		SettlementHold:       r.routeMode,
		TransferReversal:     r.routeMode,
		PartialRefund:        true,
		BeneficiaryPennyDrop: true,
		MerchantOfRecord:     false,
		SupportedCurrencies:  []money.Currency{money.INR, money.USD, money.EUR, money.GBP, money.SGD, money.AED, money.AUD, money.CAD},
	}
}

func (r *Razorpay) auth() (string, string) { return r.keyID, r.keySecret }

// ---- payments ---------------------------------------------------------------

type rzpOrder struct {
	ID        string         `json:"id"`
	Amount    int64          `json:"amount"`
	Currency  string         `json:"currency"`
	Receipt   string         `json:"receipt"`
	Status    string         `json:"status"`
	CreatedAt int64          `json:"created_at"`
	Notes     map[string]any `json:"notes"`
}

func (r *Razorpay) CreatePayment(ctx context.Context, req CreatePaymentRequest) (CreatePaymentResult, error) {
	if !r.supports(req.Amount.Currency()) {
		return CreatePaymentResult{}, fmt.Errorf("%w: %s", ErrCurrencyUnsupported, req.Amount.Currency())
	}
	if !req.Amount.IsPositive() {
		return CreatePaymentResult{}, fmt.Errorf("%w: amount must be positive", ErrProviderRejected)
	}
	if req.ReturnURL != "" {
		if err := validateCallbackURL(req.ReturnURL, r.c.allowPrivateHosts); err != nil {
			return CreatePaymentResult{}, err
		}
	}

	body := map[string]any{
		"amount":          req.Amount.Minor(),
		"currency":        string(req.Amount.Currency()),
		"receipt":         req.OrderReference,
		"payment_capture": 1,
		"notes":           stringMap(req.Notes),
	}

	if len(req.Splits) > 0 {
		if !r.routeMode {
			// Refusing beats silently dropping the split: a payment captured
			// without its instruction would settle entirely to the platform,
			// which is exactly the situation the architecture exists to avoid.
			return CreatePaymentResult{}, fmt.Errorf("%w: split settlement requires Route", ErrNotSupported)
		}
		transfers := make([]map[string]any, 0, len(req.Splits))
		var splitTotal int64
		for _, s := range req.Splits {
			if s.ProviderAccountID == "" {
				return CreatePaymentResult{}, fmt.Errorf("%w: split for %s has no linked account", ErrProviderRejected, s.SellerReference)
			}
			if s.Amount.Currency() != req.Amount.Currency() {
				return CreatePaymentResult{}, fmt.Errorf("%w: split currency %s does not match payment currency %s",
					ErrProviderRejected, s.Amount.Currency(), req.Amount.Currency())
			}
			t := map[string]any{
				"account":  s.ProviderAccountID,
				"amount":   s.Amount.Minor(),
				"currency": string(s.Amount.Currency()),
				"notes":    stringMap(s.Notes),
			}
			if s.OnHold {
				t["on_hold"] = 1
				if !s.HoldUntil.IsZero() {
					t["on_hold_until"] = s.HoldUntil.Unix()
				}
			}
			transfers = append(transfers, t)
			splitTotal += s.Amount.Minor()
		}
		if splitTotal > req.Amount.Minor() {
			return CreatePaymentResult{}, fmt.Errorf("%w: splits total %d exceed the payment amount %d",
				ErrProviderRejected, splitTotal, req.Amount.Minor())
		}
		body["transfers"] = transfers
	}

	var out rzpOrder
	user, pass := r.auth()
	if _, raw, err := r.c.do(ctx, "create_payment", request{
		Method: http.MethodPost, Path: "/v1/orders", Body: body,
		BasicUser: user, BasicPass: pass,
		IdempotencyKey: req.IdempotencyKey, Idempotent: true,
	}, &out); err != nil {
		_ = raw
		return CreatePaymentResult{}, err
	}
	if out.ID == "" {
		return CreatePaymentResult{}, fmt.Errorf("%w: provider returned no order id", ErrProviderRejected)
	}

	return CreatePaymentResult{
		ProviderIntentID: out.ID,
		Amount:           req.Amount,
		// key_id is a publishable identifier. The key SECRET never leaves the
		// server, so a client cannot mint a valid signature by itself.
		CheckoutParams: map[string]string{
			"key":      r.keyID,
			"order_id": out.ID,
			"amount":   fmt.Sprint(req.Amount.Minor()),
			"currency": string(req.Amount.Currency()),
			"name":     req.Description,
		},
		Raw: map[string]any{"id": out.ID, "status": out.Status, "amount": out.Amount},
	}, nil
}

// VerifyPayment recomputes HMAC-SHA256("<order_id>|<payment_id>") under the API
// key secret and compares in constant time.
func (r *Razorpay) VerifyPayment(_ context.Context, req VerifyPaymentRequest) (VerifyPaymentResult, error) {
	if req.ProviderIntentID == "" || req.ProviderPaymentID == "" || req.Signature == "" {
		return VerifyPaymentResult{Valid: false, Reason: "missing order id, payment id or signature"}, nil
	}
	// A signature is hex; anything else is malformed, and decoding it first
	// keeps the comparison operating on fixed-size bytes.
	mac, ok := cryptox.HexDecode(req.Signature)
	if !ok || len(mac) != 32 {
		return VerifyPaymentResult{Valid: false, Reason: "signature is not a 32-byte hex digest"}, nil
	}
	payload := req.ProviderIntentID + "|" + req.ProviderPaymentID
	if !cryptox.VerifyHMAC([]byte(r.keySecret), []byte(payload), mac) {
		return VerifyPaymentResult{Valid: false, Reason: "signature did not verify"}, nil
	}
	return VerifyPaymentResult{Valid: true}, nil
}

type rzpPayment struct {
	ID            string         `json:"id"`
	OrderID       string         `json:"order_id"`
	Amount        int64          `json:"amount"`
	Currency      string         `json:"currency"`
	Status        string         `json:"status"`
	Method        string         `json:"method"`
	CardID        string         `json:"card_id"`
	International bool           `json:"international"`
	Fee           *int64         `json:"fee"`
	Tax           *int64         `json:"tax"`
	CreatedAt     int64          `json:"created_at"`
	Captured      bool           `json:"captured"`
	ErrorCode     string         `json:"error_code"`
	Notes         map[string]any `json:"notes"`
	Card          *struct {
		Network string `json:"network"`
	} `json:"card"`
}

func (r *Razorpay) CapturePayment(ctx context.Context, req CaptureRequest) (PaymentRecord, error) {
	var out rzpPayment
	user, pass := r.auth()
	_, _, err := r.c.do(ctx, "capture_payment", request{
		Method: http.MethodPost,
		Path:   "/v1/payments/" + url.PathEscape(req.ProviderPaymentID) + "/capture",
		Body: map[string]any{
			"amount":   req.Amount.Minor(),
			"currency": string(req.Amount.Currency()),
		},
		BasicUser: user, BasicPass: pass,
		IdempotencyKey: req.IdempotencyKey, Idempotent: true,
	}, &out)
	if err != nil {
		return PaymentRecord{}, err
	}
	return r.toPaymentRecord(out)
}

func (r *Razorpay) ReconcilePayment(ctx context.Context, id string) (PaymentRecord, error) {
	var out rzpPayment
	user, pass := r.auth()
	if _, _, err := r.c.do(ctx, "reconcile_payment", request{
		Method: http.MethodGet, Path: "/v1/payments/" + url.PathEscape(id),
		BasicUser: user, BasicPass: pass, Idempotent: true,
	}, &out); err != nil {
		return PaymentRecord{}, err
	}
	return r.toPaymentRecord(out)
}

func (r *Razorpay) toPaymentRecord(p rzpPayment) (PaymentRecord, error) {
	amt, err := money.New(p.Amount, money.Currency(strings.ToUpper(p.Currency)))
	if err != nil {
		return PaymentRecord{}, fmt.Errorf("payments: provider returned currency %q: %w", p.Currency, err)
	}
	rec := PaymentRecord{
		ProviderPaymentID: p.ID,
		ProviderIntentID:  p.OrderID,
		Amount:            amt,
		Status:            mapPaymentStatus(p.Status),
		Method:            normaliseMethod(p.Method, p.International),
		International:     p.International,
		Raw:               map[string]any{"status": p.Status, "method": p.Method, "error_code": p.ErrorCode},
	}
	if p.Card != nil {
		rec.CardNetwork = strings.ToLower(p.Card.Network)
	}
	if p.Fee != nil {
		f, err := money.New(*p.Fee, amt.Currency())
		if err == nil {
			rec.Fee = &f
		}
	}
	if p.Tax != nil {
		tx, err := money.New(*p.Tax, amt.Currency())
		if err == nil {
			rec.Tax = &tx
		}
	}
	if p.CreatedAt > 0 {
		rec.CapturedAt = time.Unix(p.CreatedAt, 0).UTC()
	}
	return rec, nil
}

func mapPaymentStatus(s string) PaymentStatus {
	switch strings.ToLower(s) {
	case "created":
		return PaymentCreated
	case "authorized":
		return PaymentAuthorized
	case "captured":
		return PaymentCaptured
	case "refunded":
		return PaymentRefunded
	case "failed":
		return PaymentFailed
	}
	return PaymentStatus(strings.ToLower(s))
}

func normaliseMethod(m string, international bool) string {
	m = strings.ToLower(m)
	switch m {
	case "upi", "card", "netbanking", "wallet", "emi", "paylater":
		if m == "card" && international {
			return "international_card"
		}
		return m
	}
	return "unknown"
}

// ---- transfers --------------------------------------------------------------

type rzpTransfer struct {
	ID             string         `json:"id"`
	Account        string         `json:"recipient"`
	Amount         int64          `json:"amount"`
	Currency       string         `json:"currency"`
	Status         string         `json:"status"`
	OnHold         bool           `json:"on_hold"`
	OnHoldUntil    *int64         `json:"on_hold_until"`
	AmountReversed int64          `json:"amount_reversed"`
	Notes          map[string]any `json:"notes"`
}

func (r *Razorpay) CreateSellerTransfer(ctx context.Context, req TransferRequest) (TransferRecord, error) {
	if !r.routeMode {
		return TransferRecord{}, fmt.Errorf("%w: transfers require Route", ErrNotSupported)
	}
	if req.ProviderAccountID == "" {
		return TransferRecord{}, fmt.Errorf("%w: no linked account for seller %s", ErrAccountNotActivated, req.SellerReference)
	}
	body := map[string]any{
		"account":  req.ProviderAccountID,
		"amount":   req.Amount.Minor(),
		"currency": string(req.Amount.Currency()),
		"notes":    stringMap(req.Notes),
	}
	if req.OnHold {
		body["on_hold"] = 1
		if !req.HoldUntil.IsZero() {
			body["on_hold_until"] = req.HoldUntil.Unix()
		}
	}
	var out rzpTransfer
	user, pass := r.auth()
	if _, _, err := r.c.do(ctx, "create_transfer", request{
		Method: http.MethodPost,
		Path:   "/v1/payments/" + url.PathEscape(req.ProviderPaymentID) + "/transfers",
		Body:   body, BasicUser: user, BasicPass: pass,
		IdempotencyKey: req.IdempotencyKey, Idempotent: true,
	}, &out); err != nil {
		return TransferRecord{}, err
	}
	return r.toTransferRecord(out)
}

func (r *Razorpay) HoldSellerSettlement(ctx context.Context, transferID string, until time.Time) error {
	if !r.routeMode {
		return fmt.Errorf("%w: settlement hold requires Route", ErrNotSupported)
	}
	body := map[string]any{"on_hold": 1}
	if !until.IsZero() {
		body["on_hold_until"] = until.Unix()
	}
	user, pass := r.auth()
	_, _, err := r.c.do(ctx, "hold_transfer", request{
		Method: http.MethodPatch, Path: "/v1/transfers/" + url.PathEscape(transferID),
		Body: body, BasicUser: user, BasicPass: pass, Idempotent: true,
	}, nil)
	return err
}

func (r *Razorpay) ReleaseSellerSettlement(ctx context.Context, transferID string) error {
	if !r.routeMode {
		return fmt.Errorf("%w: settlement release requires Route", ErrNotSupported)
	}
	user, pass := r.auth()
	_, _, err := r.c.do(ctx, "release_transfer", request{
		Method: http.MethodPatch, Path: "/v1/transfers/" + url.PathEscape(transferID),
		Body: map[string]any{"on_hold": 0}, BasicUser: user, BasicPass: pass, Idempotent: true,
	}, nil)
	return err
}

func (r *Razorpay) ReconcileTransfer(ctx context.Context, id string) (TransferRecord, error) {
	var out rzpTransfer
	user, pass := r.auth()
	if _, _, err := r.c.do(ctx, "reconcile_transfer", request{
		Method: http.MethodGet, Path: "/v1/transfers/" + url.PathEscape(id),
		BasicUser: user, BasicPass: pass, Idempotent: true,
	}, &out); err != nil {
		return TransferRecord{}, err
	}
	return r.toTransferRecord(out)
}

func (r *Razorpay) toTransferRecord(t rzpTransfer) (TransferRecord, error) {
	cur := money.Currency(strings.ToUpper(t.Currency))
	amt, err := money.New(t.Amount, cur)
	if err != nil {
		return TransferRecord{}, fmt.Errorf("payments: transfer currency %q: %w", t.Currency, err)
	}
	rev, err := money.New(t.AmountReversed, cur)
	if err != nil {
		rev = money.Zero(cur)
	}
	rec := TransferRecord{
		ProviderTransferID: t.ID, ProviderAccountID: t.Account,
		Amount: amt, ReversedAmount: rev, OnHold: t.OnHold,
		Status: mapTransferStatus(t.Status, t.OnHold),
		Raw:    map[string]any{"status": t.Status, "on_hold": t.OnHold},
	}
	if t.OnHoldUntil != nil && *t.OnHoldUntil > 0 {
		rec.HoldUntil = time.Unix(*t.OnHoldUntil, 0).UTC()
	}
	return rec, nil
}

func mapTransferStatus(s string, onHold bool) TransferStatus {
	if onHold {
		return TransferOnHold
	}
	switch strings.ToLower(s) {
	case "created":
		return TransferCreated
	case "pending":
		return TransferPending
	case "processed":
		return TransferProcessed
	case "reversed":
		return TransferReversed
	case "failed":
		return TransferFailed
	}
	return TransferStatus(strings.ToLower(s))
}

// ---- refunds and reversals --------------------------------------------------

type rzpRefund struct {
	ID        string `json:"id"`
	Amount    int64  `json:"amount"`
	Currency  string `json:"currency"`
	Status    string `json:"status"`
	PaymentID string `json:"payment_id"`
}

func (r *Razorpay) RequestRefund(ctx context.Context, req RefundRequest) (RefundRecord, error) {
	body := map[string]any{
		"amount": req.Amount.Minor(),
		"speed":  "normal",
		"notes":  stringMap(req.Notes),
	}
	if req.ReverseSplits && r.routeMode {
		// reverse_all claws the seller's share back from the linked account so
		// the platform does not fund a refund out of its own pocket.
		body["reverse_all"] = 1
	}
	var out rzpRefund
	user, pass := r.auth()
	if _, _, err := r.c.do(ctx, "request_refund", request{
		Method: http.MethodPost,
		Path:   "/v1/payments/" + url.PathEscape(req.ProviderPaymentID) + "/refund",
		Body:   body, BasicUser: user, BasicPass: pass,
		IdempotencyKey: req.IdempotencyKey, Idempotent: true,
	}, &out); err != nil {
		return RefundRecord{}, err
	}
	cur := money.Currency(strings.ToUpper(out.Currency))
	if cur == "" {
		cur = req.Amount.Currency()
	}
	amt, err := money.New(out.Amount, cur)
	if err != nil {
		return RefundRecord{}, err
	}
	return RefundRecord{
		ProviderRefundID: out.ID, Amount: amt,
		Status: mapRefundStatus(out.Status),
		// The network does not return the processing fee on a refund. Recording
		// zero here would misstate unit economics, so the caller supplies the
		// retained fee from the original payment's fee data.
		FeeRetained: money.Zero(cur),
		Raw:         map[string]any{"status": out.Status},
	}, nil
}

func mapRefundStatus(s string) RefundStatus {
	switch strings.ToLower(s) {
	case "processed":
		return RefundProcessed
	case "failed":
		return RefundFailed
	}
	return RefundPending
}

func (r *Razorpay) ReverseTransfer(ctx context.Context, req ReversalRequest) (ReversalRecord, error) {
	if !r.routeMode {
		return ReversalRecord{}, fmt.Errorf("%w: reversals require Route", ErrNotSupported)
	}
	var out struct {
		ID       string `json:"id"`
		Amount   int64  `json:"amount"`
		Currency string `json:"currency"`
	}
	user, pass := r.auth()
	if _, _, err := r.c.do(ctx, "reverse_transfer", request{
		Method:    http.MethodPost,
		Path:      "/v1/transfers/" + url.PathEscape(req.ProviderTransferID) + "/reversals",
		Body:      map[string]any{"amount": req.Amount.Minor()},
		BasicUser: user, BasicPass: pass,
		IdempotencyKey: req.IdempotencyKey, Idempotent: true,
	}, &out); err != nil {
		return ReversalRecord{}, err
	}
	cur := money.Currency(strings.ToUpper(out.Currency))
	if cur == "" {
		cur = req.Amount.Currency()
	}
	amt, err := money.New(out.Amount, cur)
	if err != nil {
		amt = req.Amount
	}
	return ReversalRecord{ProviderReversalID: out.ID, Amount: amt}, nil
}

// ---- linked accounts and beneficiary validation -----------------------------

type rzpAccount struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	ActivatedAt  *int64 `json:"activated_at"`
	Requirements []struct {
		FieldReference string `json:"field_reference"`
		Status         string `json:"status"`
	} `json:"requirements"`
}

func (r *Razorpay) CreateLinkedAccount(ctx context.Context, req LinkedAccountRequest) (LinkedAccount, error) {
	body := map[string]any{
		"email":                         req.Email,
		"phone":                         req.Phone,
		"legal_business_name":           req.LegalName,
		"business_type":                 mapEntityType(req.EntityType),
		"customer_facing_business_name": req.DisplayName,
		"reference_id":                  req.SellerReference,
		"profile": map[string]any{
			"addresses": map[string]any{
				"registered": map[string]any{
					"street1":     req.AddressLine1,
					"city":        req.City,
					"state":       req.StateCode,
					"postal_code": req.Postcode,
					"country":     strings.ToLower(defaultTo(req.Country, "IN")),
				},
			},
		},
		"legal_info": pruneEmpty(map[string]any{"pan": req.PAN, "gst": req.GSTIN}),
	}
	var out rzpAccount
	user, pass := r.auth()
	if _, _, err := r.c.do(ctx, "create_linked_account", request{
		Method: http.MethodPost, Path: "/v2/accounts", Body: body,
		BasicUser: user, BasicPass: pass,
		IdempotencyKey: req.IdempotencyKey, Idempotent: true,
	}, &out); err != nil {
		return LinkedAccount{}, err
	}
	return toLinkedAccount(out), nil
}

func (r *Razorpay) FetchLinkedAccount(ctx context.Context, id string) (LinkedAccount, error) {
	var out rzpAccount
	user, pass := r.auth()
	if _, _, err := r.c.do(ctx, "fetch_linked_account", request{
		Method: http.MethodGet, Path: "/v2/accounts/" + url.PathEscape(id),
		BasicUser: user, BasicPass: pass, Idempotent: true,
	}, &out); err != nil {
		return LinkedAccount{}, err
	}
	return toLinkedAccount(out), nil
}

func toLinkedAccount(a rzpAccount) LinkedAccount {
	la := LinkedAccount{ProviderAccountID: a.ID, Status: mapAccountStatus(a.Status)}
	if a.ActivatedAt != nil && *a.ActivatedAt > 0 {
		la.ActivatedAt = time.Unix(*a.ActivatedAt, 0).UTC()
	}
	for _, rq := range a.Requirements {
		if rq.Status != "" && rq.Status != "resolved" {
			la.RequirementsUnmet = append(la.RequirementsUnmet, rq.FieldReference)
		}
	}
	// A transfer to a non-activated account can fail or hold funds, so this is
	// the only flag settlement is allowed to consult.
	la.CanReceiveTransfer = la.Status == LinkedAccountActivated && len(la.RequirementsUnmet) == 0
	return la
}

func mapAccountStatus(s string) LinkedAccountStatus {
	switch strings.ToLower(s) {
	case "created":
		return LinkedAccountCreated
	case "needs_clarification":
		return LinkedAccountNeedsClarification
	case "under_review":
		return LinkedAccountUnderReview
	case "activated":
		return LinkedAccountActivated
	case "suspended":
		return LinkedAccountSuspended
	}
	return LinkedAccountCreated
}

func mapEntityType(e string) string {
	switch e {
	case "individual", "proprietorship":
		return "individual"
	case "partnership":
		return "partnership"
	case "llp":
		return "llp"
	case "private_limited":
		return "private_limited"
	case "public_limited":
		return "public_limited"
	case "trust":
		return "trust"
	case "society":
		return "society"
	}
	return "individual"
}

type rzpValidation struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Results struct {
		AccountStatus  string `json:"account_status"`
		RegisteredName string `json:"registered_name"`
	} `json:"results"`
}

// ValidateBeneficiary performs a penny-drop through the provider's fund-account
// validation API. No payout is permitted to an unvalidated destination.
func (r *Razorpay) ValidateBeneficiary(ctx context.Context, req BeneficiaryRequest) (BeneficiaryResult, error) {
	fa := map[string]any{
		"account_type": "bank_account",
		"bank_account": map[string]any{
			"name":           req.BeneficiaryName,
			"ifsc":           req.IFSC,
			"account_number": req.AccountNumber,
		},
	}
	if req.VPA != "" {
		fa = map[string]any{"account_type": "vpa", "vpa": map[string]any{"address": req.VPA}}
	}
	var out rzpValidation
	user, pass := r.auth()
	if _, _, err := r.c.do(ctx, "validate_beneficiary", request{
		Method: http.MethodPost, Path: "/v1/fund_accounts/validations",
		Body: map[string]any{
			"account":  fa,
			"amount":   100, // one rupee, refunded by the bank
			"currency": "INR",
			"notes":    map[string]string{"seller": req.SellerReference},
		},
		BasicUser: user, BasicPass: pass,
		IdempotencyKey: req.IdempotencyKey, Idempotent: true,
	}, &out); err != nil {
		return BeneficiaryResult{}, err
	}
	valid := strings.EqualFold(out.Status, "completed") && strings.EqualFold(out.Results.AccountStatus, "active")
	res := BeneficiaryResult{
		Valid:          valid,
		RegisteredName: out.Results.RegisteredName,
		Reference:      out.ID,
		Raw:            map[string]any{"status": out.Status, "account_status": out.Results.AccountStatus},
	}
	if !valid {
		res.Reason = "the bank did not confirm an active account for these details"
	}
	res.NameMatchScore = NameMatchScore(req.BeneficiaryName, out.Results.RegisteredName)
	return res, nil
}

// ---- webhooks ---------------------------------------------------------------

type rzpWebhook struct {
	Entity    string   `json:"entity"`
	AccountID string   `json:"account_id"`
	Event     string   `json:"event"`
	Contains  []string `json:"contains"`
	CreatedAt int64    `json:"created_at"`
	Payload   map[string]struct {
		Entity map[string]any `json:"entity"`
	} `json:"payload"`
}

// ParseWebhook verifies X-Razorpay-Signature as HMAC-SHA256 over the exact raw
// body under the WEBHOOK secret (not the API key secret) and normalises the
// event.
//
// The body must be the untouched bytes: re-encoding JSON before verification is
// a classic way to break signature checks, or worse, to appear to pass them.
func (r *Razorpay) ParseWebhook(_ context.Context, header http.Header, rawBody []byte) (WebhookEvent, error) {
	sig := header.Get("X-Razorpay-Signature")
	if sig == "" {
		return WebhookEvent{}, fmt.Errorf("%w: no X-Razorpay-Signature header", ErrInvalidSignature)
	}
	mac, ok := cryptox.HexDecode(sig)
	if !ok || len(mac) != 32 {
		return WebhookEvent{}, fmt.Errorf("%w: signature is not a 32-byte hex digest", ErrInvalidSignature)
	}
	if !cryptox.VerifyHMAC([]byte(r.webhookSecret), rawBody, mac) {
		return WebhookEvent{}, ErrInvalidSignature
	}

	var w rzpWebhook
	if err := json.Unmarshal(rawBody, &w); err != nil {
		return WebhookEvent{}, fmt.Errorf("%w: body did not parse as a webhook", ErrProviderRejected)
	}
	if w.Event == "" {
		return WebhookEvent{}, fmt.Errorf("%w: webhook has no event type", ErrProviderRejected)
	}

	ev := WebhookEvent{
		Provider: r.Name(),
		// Razorpay sends X-Razorpay-Event-Id; where absent we derive a stable
		// key from the signature, which is a function of the exact body, so
		// de-duplication still holds.
		EventID: defaultTo(header.Get("X-Razorpay-Event-Id"), "sig:"+sig),
		Type:    w.Event,
		Raw:     map[string]any{"event": w.Event, "account_id": w.AccountID},
		RawBody: rawBody,
	}
	if w.CreatedAt > 0 {
		ev.CreatedAt = time.Unix(w.CreatedAt, 0).UTC()
	} else {
		ev.CreatedAt = time.Now().UTC()
	}

	for key, wrapper := range w.Payload {
		e := wrapper.Entity
		if e == nil {
			continue
		}
		id, _ := e["id"].(string)
		switch key {
		case "payment":
			ev.ProviderPaymentID = id
			if oid, ok := e["order_id"].(string); ok {
				ev.ProviderIntentID = oid
			}
			ev.Status, _ = e["status"].(string)
			ev.Amount = amountFrom(e)
		case "order":
			if ev.ProviderIntentID == "" {
				ev.ProviderIntentID = id
			}
		case "transfer":
			ev.ProviderTransferID = id
			if ev.Status == "" {
				ev.Status, _ = e["status"].(string)
			}
			if ev.Amount == nil {
				ev.Amount = amountFrom(e)
			}
		case "refund":
			ev.ProviderRefundID = id
			if pid, ok := e["payment_id"].(string); ok && ev.ProviderPaymentID == "" {
				ev.ProviderPaymentID = pid
			}
			if ev.Amount == nil {
				ev.Amount = amountFrom(e)
			}
		case "dispute":
			ev.ProviderDisputeID = id
			if pid, ok := e["payment_id"].(string); ok && ev.ProviderPaymentID == "" {
				ev.ProviderPaymentID = pid
			}
			if ev.Amount == nil {
				ev.Amount = amountFrom(e)
			}
		case "account":
			ev.ProviderAccountID = id
			if ev.Status == "" {
				ev.Status, _ = e["status"].(string)
			}
		}
		ev.Raw[key] = e
	}
	return ev, nil
}

func amountFrom(e map[string]any) *money.Money {
	amtRaw, ok := e["amount"]
	if !ok {
		return nil
	}
	curRaw, _ := e["currency"].(string)
	if curRaw == "" {
		curRaw = "INR"
	}
	var minor int64
	switch v := amtRaw.(type) {
	case float64:
		// JSON numbers arrive as float64. Amounts are integral paise and well
		// within float64's exact-integer range, but the conversion is checked
		// so a fractional or out-of-range value is dropped rather than rounded.
		if v != float64(int64(v)) || v > 9e15 || v < -9e15 {
			return nil
		}
		minor = int64(v)
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return nil
		}
		minor = n
	default:
		return nil
	}
	m, err := money.New(minor, money.Currency(strings.ToUpper(curRaw)))
	if err != nil {
		return nil
	}
	return &m
}

func (r *Razorpay) supports(c money.Currency) bool {
	for _, s := range r.Capabilities().SupportedCurrencies {
		if s == c {
			return true
		}
	}
	return false
}

// ---- shared helpers ---------------------------------------------------------

func stringMap(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	// Provider note fields are size-limited; oversize values are truncated
	// rather than causing the whole payment to be rejected.
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[truncate(k, 64)] = truncate(v, 256)
	}
	return out
}

func pruneEmpty(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		out[k] = v
	}
	return out
}

func defaultTo(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// validateCallbackURL refuses anything that is not an absolute https URL on a
// public host, because a callback URL we send onward is a redirect we are
// asking a third party to perform on a user's browser.
func validateCallbackURL(raw string, allowPrivate bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: callback URL %q is not absolute", ErrProviderRejected, raw)
	}
	if u.Scheme != "https" && !allowPrivate {
		return fmt.Errorf("%w: callback URL must be https", ErrProviderRejected)
	}
	if !allowPrivate {
		host := u.Hostname()
		if ip := net.ParseIP(host); ip != nil && isDisallowedIP(ip) {
			return fmt.Errorf("%w: callback URL points at a non-public address", ErrProviderRejected)
		}
	}
	return nil
}

// NameMatchScore is a cheap 0-100 similarity between a claimed beneficiary name
// and the name the bank holds, used to catch both typos and payout hijacking.
// It is intentionally simple and explainable: a reviewer can predict its output.
func NameMatchScore(claimed, registered string) int {
	a := normaliseName(claimed)
	b := normaliseName(registered)
	if a == "" || b == "" {
		return 0
	}
	if a == b {
		return 100
	}
	// Token overlap (Jaccard), which handles reordered and abbreviated names
	// far better than edit distance does.
	at := strings.Fields(a)
	bt := strings.Fields(b)
	set := make(map[string]bool, len(at))
	for _, t := range at {
		set[t] = true
	}
	inter := 0
	for _, t := range bt {
		if set[t] {
			inter++
			delete(set, t)
		}
	}
	union := len(at) + len(bt) - inter
	if union == 0 {
		return 0
	}
	return inter * 100 / union
}

func normaliseName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevSpace = false
		default:
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
		}
	}
	out := strings.TrimSpace(b.String())
	// Drop honorifics and the suffixes Indian bank records commonly carry.
	drop := map[string]bool{"mr": true, "mrs": true, "ms": true, "shri": true, "smt": true,
		"dr": true, "m s": true, "pvt": true, "private": true, "ltd": true, "limited": true}
	fields := strings.Fields(out)
	kept := fields[:0]
	for _, f := range fields {
		if !drop[f] {
			kept = append(kept, f)
		}
	}
	return strings.Join(kept, " ")
}

var _ Provider = (*Razorpay)(nil)
