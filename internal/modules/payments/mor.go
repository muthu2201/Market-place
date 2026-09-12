package payments

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/muthu2201/market-place/internal/platform/cryptox"
	"github.com/muthu2201/market-place/internal/platform/metrics"
	"github.com/muthu2201/market-place/internal/platform/money"
)

// MerchantOfRecord adapts a merchant-of-record provider (Paddle, Lemon Squeezy,
// Polar and similar) to the same port.
//
// Under an MoR the provider is the legal seller to the end customer and takes on
// destination-country tax registration and remittance: EU VAT through OSS/IOSS,
// US marketplace-facilitator sales tax, UK VAT. For a small Indian operator that
// is the difference between selling globally and registering for tax in dozens
// of jurisdictions.
//
// Two consequences are modelled honestly rather than hidden:
//
//   - The MoR computes and holds destination tax itself, so this platform's
//     own GST/TCS/TDS engine must NOT also add buyer-facing tax on those sales.
//     Capabilities().MerchantOfRecord is the flag the checkout path branches on.
//   - Payouts arrive periodically and in aggregate, not per order. Settlement is
//     therefore reconciled from the provider's payout report, and split
//     settlement is unsupported.
type MerchantOfRecord struct {
	c             *client
	vendor        string
	apiKey        string
	webhookSecret string
	// signatureHeader and signatureScheme differ between vendors; both are
	// explicit so a misconfiguration fails loudly rather than silently
	// accepting unverified webhooks.
	signatureHeader string
}

// MoRConfig configures the adapter.
type MoRConfig struct {
	Vendor            string // "paddle", "lemonsqueezy", "polar"
	BaseURL           string
	APIKey            string
	WebhookSecret     string
	Timeout           time.Duration
	MaxRetries        int
	Metrics           *metrics.App
	AllowPrivateHosts bool
}

// NewMerchantOfRecord builds the adapter.
func NewMerchantOfRecord(cfg MoRConfig) (*MerchantOfRecord, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("payments: merchant-of-record adapter requires an API key")
	}
	if cfg.WebhookSecret == "" {
		return nil, fmt.Errorf("payments: merchant-of-record adapter requires a webhook secret")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("payments: merchant-of-record adapter requires a base URL")
	}
	header := "X-Signature"
	switch strings.ToLower(cfg.Vendor) {
	case "paddle":
		header = "Paddle-Signature"
	case "lemonsqueezy":
		header = "X-Signature"
	case "polar":
		header = "Webhook-Signature"
	case "":
		return nil, fmt.Errorf("payments: merchant-of-record adapter requires a vendor name")
	}
	c, err := newClient(clientOptions{
		BaseURL: cfg.BaseURL, Timeout: cfg.Timeout, MaxRetries: cfg.MaxRetries,
		Metrics: cfg.Metrics, Provider: "mor", AllowPrivateHosts: cfg.AllowPrivateHosts,
	})
	if err != nil {
		return nil, err
	}
	return &MerchantOfRecord{
		c: c, vendor: strings.ToLower(cfg.Vendor), apiKey: cfg.APIKey,
		webhookSecret: cfg.WebhookSecret, signatureHeader: header,
	}, nil
}

func (m *MerchantOfRecord) Name() string { return "mor" }

// Vendor names the underlying provider, for the ledger and for reconciliation.
func (m *MerchantOfRecord) Vendor() string { return m.vendor }

func (m *MerchantOfRecord) Capabilities() Capabilities {
	return Capabilities{
		SplitSettlement:      false,
		SettlementHold:       false,
		TransferReversal:     false,
		PartialRefund:        true,
		BeneficiaryPennyDrop: false,
		MerchantOfRecord:     true,
		SupportedCurrencies: []money.Currency{
			money.USD, money.EUR, money.GBP, money.INR, money.AUD, money.CAD, money.SGD, money.AED, money.JPY,
		},
	}
}

func (m *MerchantOfRecord) CreatePayment(ctx context.Context, req CreatePaymentRequest) (CreatePaymentResult, error) {
	if len(req.Splits) > 0 {
		return CreatePaymentResult{}, fmt.Errorf("%w: a merchant of record settles in aggregate, not per split", ErrNotSupported)
	}
	if req.ReturnURL != "" {
		if err := validateCallbackURL(req.ReturnURL, m.c.allowPrivateHosts); err != nil {
			return CreatePaymentResult{}, err
		}
	}
	var out struct {
		ID        string `json:"id"`
		URL       string `json:"url"`
		ExpiresAt string `json:"expires_at"`
	}
	if _, _, err := m.c.do(ctx, "create_payment", request{
		Method: http.MethodPost, Path: "/v1/checkouts",
		Body: map[string]any{
			"amount":         req.Amount.Minor(),
			"currency":       string(req.Amount.Currency()),
			"reference":      req.OrderReference,
			"customer_email": req.CustomerEmail,
			"description":    req.Description,
			"success_url":    req.ReturnURL,
			"metadata":       stringMap(req.Notes),
		},
		Bearer: m.apiKey, IdempotencyKey: req.IdempotencyKey, Idempotent: true,
	}, &out); err != nil {
		return CreatePaymentResult{}, err
	}
	res := CreatePaymentResult{
		ProviderIntentID: out.ID, Amount: req.Amount,
		CheckoutParams: map[string]string{"checkout_url": out.URL, "vendor": m.vendor},
	}
	if out.ExpiresAt != "" {
		if ts, err := time.Parse(time.RFC3339, out.ExpiresAt); err == nil {
			res.ExpiresAt = ts
		}
	}
	return res, nil
}

// VerifyPayment has no client-side callback signature under an MoR model: the
// authoritative signal is the server-to-server webhook. Returning "not valid"
// with a reason is safer than returning "valid" for an unverifiable input.
func (m *MerchantOfRecord) VerifyPayment(context.Context, VerifyPaymentRequest) (VerifyPaymentResult, error) {
	return VerifyPaymentResult{
		Valid:  false,
		Reason: "a merchant-of-record sale is confirmed by its signed webhook, not by a browser callback",
	}, nil
}

func (m *MerchantOfRecord) CapturePayment(ctx context.Context, req CaptureRequest) (PaymentRecord, error) {
	// MoR checkouts capture themselves; re-reading is the honest implementation.
	return m.ReconcilePayment(ctx, req.ProviderPaymentID)
}

func (m *MerchantOfRecord) CreateSellerTransfer(context.Context, TransferRequest) (TransferRecord, error) {
	return TransferRecord{}, fmt.Errorf("%w: settle merchant-of-record sales from the payout report", ErrNotSupported)
}

func (m *MerchantOfRecord) HoldSellerSettlement(context.Context, string, time.Time) error {
	return fmt.Errorf("%w: holds are applied to our own payout schedule, not at the provider", ErrNotSupported)
}

func (m *MerchantOfRecord) ReleaseSellerSettlement(context.Context, string) error {
	return fmt.Errorf("%w: holds are applied to our own payout schedule, not at the provider", ErrNotSupported)
}

func (m *MerchantOfRecord) ReverseTransfer(context.Context, ReversalRequest) (ReversalRecord, error) {
	return ReversalRecord{}, fmt.Errorf("%w: recover from the seller's next settlement instead", ErrNotSupported)
}

func (m *MerchantOfRecord) RequestRefund(ctx context.Context, req RefundRequest) (RefundRecord, error) {
	var out struct {
		ID          string `json:"id"`
		Amount      int64  `json:"amount"`
		Currency    string `json:"currency"`
		Status      string `json:"status"`
		FeeRetained int64  `json:"fee_retained"`
	}
	if _, _, err := m.c.do(ctx, "request_refund", request{
		Method: http.MethodPost, Path: "/v1/payments/" + url.PathEscape(req.ProviderPaymentID) + "/refunds",
		Body: map[string]any{
			"amount": req.Amount.Minor(), "reason": req.Reason, "metadata": stringMap(req.Notes),
		},
		Bearer: m.apiKey, IdempotencyKey: req.IdempotencyKey, Idempotent: true,
	}, &out); err != nil {
		return RefundRecord{}, err
	}
	cur := money.Currency(strings.ToUpper(defaultTo(out.Currency, string(req.Amount.Currency()))))
	amt, err := money.New(out.Amount, cur)
	if err != nil {
		return RefundRecord{}, err
	}
	fee, err := money.New(out.FeeRetained, cur)
	if err != nil {
		fee = money.Zero(cur)
	}
	return RefundRecord{
		ProviderRefundID: out.ID, Amount: amt, FeeRetained: fee,
		Status: mapRefundStatus(out.Status),
	}, nil
}

func (m *MerchantOfRecord) ReconcilePayment(ctx context.Context, id string) (PaymentRecord, error) {
	var out struct {
		ID       string `json:"id"`
		Checkout string `json:"checkout_id"`
		Amount   int64  `json:"amount"`
		Currency string `json:"currency"`
		Status   string `json:"status"`
		Method   string `json:"method"`
		Fee      *int64 `json:"fee"`
		Tax      *int64 `json:"tax"`
		PaidAt   string `json:"paid_at"`
	}
	if _, _, err := m.c.do(ctx, "reconcile_payment", request{
		Method: http.MethodGet, Path: "/v1/payments/" + url.PathEscape(id),
		Bearer: m.apiKey, Idempotent: true,
	}, &out); err != nil {
		return PaymentRecord{}, err
	}
	cur := money.Currency(strings.ToUpper(out.Currency))
	amt, err := money.New(out.Amount, cur)
	if err != nil {
		return PaymentRecord{}, fmt.Errorf("payments: mor currency %q: %w", out.Currency, err)
	}
	rec := PaymentRecord{
		ProviderPaymentID: out.ID, ProviderIntentID: out.Checkout, Amount: amt,
		Status: mapPaymentStatus(out.Status), Method: out.Method,
		Raw: map[string]any{"vendor": m.vendor, "status": out.Status},
	}
	if out.Fee != nil {
		if f, err := money.New(*out.Fee, cur); err == nil {
			rec.Fee = &f
		}
	}
	if out.Tax != nil {
		if tx, err := money.New(*out.Tax, cur); err == nil {
			rec.Tax = &tx
		}
	}
	if out.PaidAt != "" {
		if ts, err := time.Parse(time.RFC3339, out.PaidAt); err == nil {
			rec.CapturedAt = ts
		}
	}
	return rec, nil
}

func (m *MerchantOfRecord) ReconcileTransfer(context.Context, string) (TransferRecord, error) {
	return TransferRecord{}, fmt.Errorf("%w: reconcile against the payout report", ErrNotSupported)
}

func (m *MerchantOfRecord) CreateLinkedAccount(_ context.Context, req LinkedAccountRequest) (LinkedAccount, error) {
	// Under an MoR there is no sub-merchant: the provider's counterparty is us.
	// Returning a synthetic activated account keeps the onboarding flow uniform
	// while making it obvious in the ledger which model produced it.
	return LinkedAccount{
		ProviderAccountID: "mor:" + req.SellerReference,
		Status:            LinkedAccountActivated,
		//archcheck:allow wall-clock time -- a merchant-of-record has no sub-merchant to activate; this synthetic timestamp keeps the onboarding shape uniform.
		ActivatedAt:        time.Now().UTC(),
		CanReceiveTransfer: false,
		Raw:                map[string]any{"model": "merchant_of_record", "vendor": m.vendor},
	}, nil
}

func (m *MerchantOfRecord) FetchLinkedAccount(ctx context.Context, id string) (LinkedAccount, error) {
	return m.CreateLinkedAccount(ctx, LinkedAccountRequest{SellerReference: strings.TrimPrefix(id, "mor:")})
}

func (m *MerchantOfRecord) ValidateBeneficiary(context.Context, BeneficiaryRequest) (BeneficiaryResult, error) {
	return BeneficiaryResult{}, fmt.Errorf("%w: beneficiary validation belongs to the payout rail, not the MoR", ErrNotSupported)
}

// ParseWebhook verifies the vendor's signature over the exact raw body.
func (m *MerchantOfRecord) ParseWebhook(_ context.Context, header http.Header, rawBody []byte) (WebhookEvent, error) {
	sig := header.Get(m.signatureHeader)
	if sig == "" {
		return WebhookEvent{}, fmt.Errorf("%w: no %s header", ErrInvalidSignature, m.signatureHeader)
	}
	// Paddle sends "ts=<unix>;h1=<hex>" and signs "<ts>:<body>"; the others send
	// a bare hex digest over the body. Both are handled explicitly.
	var signedPayload []byte
	digest := sig
	if ts, h1, ok := parsePaddleSignature(sig); ok {
		signedPayload = append(append([]byte(ts), ':'), rawBody...)
		digest = h1
		if age := time.Since(time.Unix(parseUnix(ts), 0)); age > 5*time.Minute || age < -5*time.Minute {
			// A stale timestamp is a replay; refusing it is the point of signing it.
			return WebhookEvent{}, fmt.Errorf("%w: signature timestamp is outside the accepted window", ErrInvalidSignature)
		}
	} else {
		signedPayload = rawBody
	}
	mac, ok := cryptox.HexDecode(digest)
	if !ok || len(mac) != 32 {
		return WebhookEvent{}, fmt.Errorf("%w: signature is not a 32-byte hex digest", ErrInvalidSignature)
	}
	if !cryptox.VerifyHMAC([]byte(m.webhookSecret), signedPayload, mac) {
		return WebhookEvent{}, ErrInvalidSignature
	}

	var body struct {
		ID        string         `json:"id"`
		EventID   string         `json:"event_id"`
		Type      string         `json:"event_type"`
		AltType   string         `json:"type"`
		CreatedAt string         `json:"occurred_at"`
		Data      map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rawBody, &body); err != nil {
		return WebhookEvent{}, fmt.Errorf("%w: body did not parse", ErrProviderRejected)
	}
	ev := WebhookEvent{
		Provider: "mor",
		EventID:  defaultTo(body.EventID, defaultTo(body.ID, "sig:"+digest)),
		Type:     defaultTo(body.Type, body.AltType),
		Raw:      map[string]any{"vendor": m.vendor, "data": body.Data},
		RawBody:  rawBody,
	}
	if ev.Type == "" {
		return WebhookEvent{}, fmt.Errorf("%w: webhook has no event type", ErrProviderRejected)
	}
	if body.CreatedAt != "" {
		if ts, err := time.Parse(time.RFC3339, body.CreatedAt); err == nil {
			ev.CreatedAt = ts
		}
	}
	if ev.CreatedAt.IsZero() {
		//archcheck:allow wall-clock time -- fallback when the vendor omits a timestamp; an adapter-boundary default.
		ev.CreatedAt = time.Now().UTC()
	}
	if body.Data != nil {
		ev.ProviderPaymentID, _ = body.Data["id"].(string)
		ev.ProviderIntentID, _ = body.Data["checkout_id"].(string)
		ev.ProviderRefundID, _ = body.Data["refund_id"].(string)
		ev.Status, _ = body.Data["status"].(string)
		ev.Amount = amountFrom(body.Data)
	}
	return ev, nil
}

func parsePaddleSignature(s string) (ts, h1 string, ok bool) {
	for _, part := range strings.Split(s, ";") {
		k, v, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		switch k {
		case "ts":
			ts = v
		case "h1":
			h1 = v
		}
	}
	return ts, h1, ts != "" && h1 != ""
}

func parseUnix(s string) int64 {
	var v int64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0
		}
		v = v*10 + int64(s[i]-'0')
	}
	return v
}

var _ Provider = (*MerchantOfRecord)(nil)
