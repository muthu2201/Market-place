// Package payments defines the provider port and its adapters.
//
// The port exists for one structural reason and one commercial one.
//
// Structural: the platform must never hold customer funds. Under the RBI
// (Regulation of Payment Aggregators) Directions, 2025 a non-bank payment
// aggregator needs INR 15 crore of net worth at application rising to INR 25
// crore, must hold funds in escrow with a scheduled commercial bank, and is
// explicitly barred from running a marketplace. Split settlement by a licensed
// provider keeps this platform a facilitator rather than a PA, and the port is
// what keeps that property from leaking into business logic.
//
// Commercial: Razorpay Route activation requires evidenced turnover that a
// pre-revenue platform does not have. The launch adapter is therefore "bridge"
// (single-merchant collection plus separately reconciled payouts), with
// "razorpay_route" and "mor" behind the same interface. Switching provider is a
// configuration change, not a rewrite, and the double-entry ledger plus the
// webhook de-duplication table make the switch safe.
package payments

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/muthu2201/market-place/internal/platform/money"
)

// Provider is the payment port. Every method is idempotent on the supplied
// IdempotencyKey; callers may retry freely.
type Provider interface {
	// Name identifies the adapter in the ledger, in metrics and in logs.
	Name() string

	// Capabilities lets callers branch on what this provider can actually do
	// rather than on its name.
	Capabilities() Capabilities

	// CreatePayment opens a payment for an order, including the split
	// instruction where the provider supports it.
	CreatePayment(ctx context.Context, req CreatePaymentRequest) (CreatePaymentResult, error)

	// VerifyPayment recomputes the provider's signature over the documented
	// payload. A payment that does not verify is never honoured, whatever the
	// client says.
	VerifyPayment(ctx context.Context, req VerifyPaymentRequest) (VerifyPaymentResult, error)

	// CapturePayment captures an authorised payment.
	CapturePayment(ctx context.Context, req CaptureRequest) (PaymentRecord, error)

	// CreateSellerTransfer moves a seller's share to their linked account.
	CreateSellerTransfer(ctx context.Context, req TransferRequest) (TransferRecord, error)

	// HoldSellerSettlement keeps a transfer un-settled during the protection
	// window. This, not a wallet, is how chargeback exposure is contained.
	HoldSellerSettlement(ctx context.Context, transferID string, until time.Time) error

	// ReleaseSellerSettlement settles a held transfer.
	ReleaseSellerSettlement(ctx context.Context, transferID string) error

	// RequestRefund refunds all or part of a payment.
	RequestRefund(ctx context.Context, req RefundRequest) (RefundRecord, error)

	// ReverseTransfer claws back a transfer, fully or partially.
	ReverseTransfer(ctx context.Context, req ReversalRequest) (ReversalRecord, error)

	// ReconcilePayment re-reads a payment from the provider as the source of truth.
	ReconcilePayment(ctx context.Context, providerPaymentID string) (PaymentRecord, error)

	// ReconcileTransfer re-reads a transfer from the provider.
	ReconcileTransfer(ctx context.Context, providerTransferID string) (TransferRecord, error)

	// ParseWebhook verifies the signature and normalises the event. It returns
	// ErrInvalidSignature for anything that does not verify, and the caller
	// must treat that as hostile input rather than as a transient failure.
	ParseWebhook(ctx context.Context, header http.Header, rawBody []byte) (WebhookEvent, error)

	// CreateLinkedAccount onboards a seller as a sub-merchant.
	CreateLinkedAccount(ctx context.Context, req LinkedAccountRequest) (LinkedAccount, error)

	// FetchLinkedAccount re-reads onboarding state. Settlement is gated on the
	// provider's own view of KYC, never on ours: transferring to an account the
	// provider has not activated can fail or hold funds.
	FetchLinkedAccount(ctx context.Context, providerAccountID string) (LinkedAccount, error)

	// ValidateBeneficiary performs a penny-drop or equivalent name check before
	// any money is sent to a bank account.
	ValidateBeneficiary(ctx context.Context, req BeneficiaryRequest) (BeneficiaryResult, error)
}

// Capabilities describes what an adapter supports.
type Capabilities struct {
	SplitSettlement      bool
	SettlementHold       bool
	TransferReversal     bool
	PartialRefund        bool
	BeneficiaryPennyDrop bool
	// MerchantOfRecord means the provider is the legal seller and handles
	// destination-country tax registration and remittance itself.
	MerchantOfRecord bool
	// SupportedCurrencies is advisory; a request in another currency is refused.
	SupportedCurrencies []money.Currency
}

// ---- requests and results ---------------------------------------------------

// SplitLine instructs the provider to route part of a payment to a sub-merchant.
type SplitLine struct {
	SellerReference   string // our seller public id, echoed back for reconciliation
	ProviderAccountID string
	Amount            money.Money
	// OnHold keeps this share un-settled until HoldUntil.
	OnHold    bool
	HoldUntil time.Time
	Notes     map[string]string
}

type CreatePaymentRequest struct {
	OrderReference string // our order public id
	Amount         money.Money
	// Splits may be empty when the adapter does not support split settlement;
	// the bridge adapter reconciles and pays out separately instead.
	Splits         []SplitLine
	CustomerEmail  string
	CustomerName   string
	Description    string
	IdempotencyKey string
	// ReturnURL and NotifyURL are absolute, https in production, and are
	// validated by the adapter before they are sent onward.
	ReturnURL string
	Notes     map[string]string
}

type CreatePaymentResult struct {
	ProviderIntentID string
	// CheckoutParams are handed to the browser SDK. They never contain a secret
	// that would let a client authorise a payment on its own.
	CheckoutParams map[string]string
	Amount         money.Money
	ExpiresAt      time.Time
	Raw            map[string]any
}

type VerifyPaymentRequest struct {
	ProviderIntentID  string
	ProviderPaymentID string
	Signature         string
}

type VerifyPaymentResult struct {
	Valid  bool
	Reason string
}

type CaptureRequest struct {
	ProviderPaymentID string
	Amount            money.Money
	IdempotencyKey    string
}

// PaymentRecord is the provider's own view of a payment: the reconciliation
// source of truth.
type PaymentRecord struct {
	ProviderPaymentID string
	ProviderIntentID  string
	Amount            money.Money
	Status            PaymentStatus
	Method            string
	CardNetwork       string
	// Fee and Tax are what the provider actually charged. They are frequently
	// unknown at capture time and arrive with settlement data.
	Fee           *money.Money
	Tax           *money.Money
	CapturedAt    time.Time
	International bool
	Raw           map[string]any
}

type PaymentStatus string

const (
	PaymentCreated    PaymentStatus = "created"
	PaymentAuthorized PaymentStatus = "authorized"
	PaymentCaptured   PaymentStatus = "captured"
	PaymentFailed     PaymentStatus = "failed"
	PaymentRefunded   PaymentStatus = "refunded"
)

type TransferRequest struct {
	ProviderPaymentID string
	ProviderAccountID string
	SellerReference   string
	OrderItemRef      string
	Amount            money.Money
	OnHold            bool
	HoldUntil         time.Time
	IdempotencyKey    string
	Notes             map[string]string
}

type TransferRecord struct {
	ProviderTransferID string
	ProviderAccountID  string
	Amount             money.Money
	Status             TransferStatus
	OnHold             bool
	HoldUntil          time.Time
	ReversedAmount     money.Money
	Raw                map[string]any
}

type TransferStatus string

const (
	TransferPending   TransferStatus = "pending"
	TransferOnHold    TransferStatus = "on_hold"
	TransferCreated   TransferStatus = "created"
	TransferProcessed TransferStatus = "processed"
	TransferReversed  TransferStatus = "reversed"
	TransferFailed    TransferStatus = "failed"
)

type RefundRequest struct {
	ProviderPaymentID string
	Amount            money.Money
	Reason            string
	IdempotencyKey    string
	// ReverseSplits asks the provider to claw the seller's share back from the
	// linked account as part of the refund, where it supports that.
	ReverseSplits bool
	Notes         map[string]string
}

type RefundRecord struct {
	ProviderRefundID string
	Amount           money.Money
	Status           RefundStatus
	// FeeRetained records processing cost the network does not return. It is
	// not zero, and pretending otherwise is how a marketplace discovers its
	// refund policy is loss-making.
	FeeRetained money.Money
	Raw         map[string]any
}

type RefundStatus string

const (
	RefundPending   RefundStatus = "pending"
	RefundProcessed RefundStatus = "processed"
	RefundFailed    RefundStatus = "failed"
)

type ReversalRequest struct {
	ProviderTransferID string
	Amount             money.Money
	IdempotencyKey     string
}

type ReversalRecord struct {
	ProviderReversalID string
	Amount             money.Money
	Raw                map[string]any
}

type LinkedAccountRequest struct {
	SellerReference string
	LegalName       string
	DisplayName     string
	Email           string
	Phone           string
	EntityType      string
	PAN             string
	GSTIN           string
	AddressLine1    string
	City            string
	StateCode       string
	Postcode        string
	Country         string
	IdempotencyKey  string
}

type LinkedAccount struct {
	ProviderAccountID string
	Status            LinkedAccountStatus
	// ActivatedAt is set only when the PROVIDER says KYC is complete. The
	// platform gates settlement on this, never on its own record.
	ActivatedAt        time.Time
	RequirementsUnmet  []string
	CanReceiveTransfer bool
	Raw                map[string]any
}

type LinkedAccountStatus string

const (
	LinkedAccountCreated            LinkedAccountStatus = "created"
	LinkedAccountNeedsClarification LinkedAccountStatus = "needs_clarification"
	LinkedAccountUnderReview        LinkedAccountStatus = "under_review"
	LinkedAccountActivated          LinkedAccountStatus = "activated"
	LinkedAccountSuspended          LinkedAccountStatus = "suspended"
)

type BeneficiaryRequest struct {
	SellerReference string
	AccountNumber   string
	IFSC            string
	BeneficiaryName string
	VPA             string
	IdempotencyKey  string
}

type BeneficiaryResult struct {
	Valid bool
	// RegisteredName is what the bank holds. A mismatch against the seller's
	// claimed name is the signal that catches both typos and payout hijacking.
	RegisteredName string
	NameMatchScore int
	Reference      string
	Reason         string
	Raw            map[string]any
}

// ---- webhooks ---------------------------------------------------------------

// WebhookEvent is the normalised, signature-verified provider notification.
type WebhookEvent struct {
	Provider string
	// EventID is the provider's own identifier and is the de-duplication key.
	EventID   string
	Type      string
	CreatedAt time.Time
	// Canonical fields extracted from the payload, so consumers do not reach
	// into provider-shaped JSON.
	ProviderPaymentID  string
	ProviderIntentID   string
	ProviderTransferID string
	ProviderRefundID   string
	ProviderDisputeID  string
	ProviderAccountID  string
	Amount             *money.Money
	Status             string
	// Raw is retained for audit and for reconciliation of fields we do not yet
	// model. It is stored as-is in provider_webhook_events.
	Raw map[string]any
	// RawBody is the exact bytes whose signature was verified; its digest is
	// stored so a replay carrying altered content is detectable.
	RawBody []byte
}

// ---- errors -----------------------------------------------------------------

var (
	// ErrInvalidSignature means the payload did not authenticate. Treat it as
	// hostile input: do not retry, do not process, do log.
	ErrInvalidSignature = errors.New("payments: provider signature did not verify")
	// ErrNotSupported means this adapter cannot perform the operation.
	ErrNotSupported = errors.New("payments: operation not supported by this provider")
	// ErrProviderRejected is a definite refusal; retrying will not help.
	ErrProviderRejected = errors.New("payments: provider rejected the request")
	// ErrProviderUnavailable is transient; the caller should retry with backoff.
	ErrProviderUnavailable = errors.New("payments: provider temporarily unavailable")
	// ErrNotFound means the provider has no such object.
	ErrNotFound = errors.New("payments: object not found at provider")
	// ErrCurrencyUnsupported means the adapter cannot process this currency.
	ErrCurrencyUnsupported = errors.New("payments: currency not supported by this provider")
	// ErrAccountNotActivated means the seller's linked account cannot yet
	// receive a transfer. Transferring anyway can fail or hold funds.
	ErrAccountNotActivated = errors.New("payments: linked account is not activated for transfers")
)

// ProviderError carries the provider's own code alongside our classification.
type ProviderError struct {
	Op      string
	Code    string
	Message string
	Status  int
	Class   error
}

func (e *ProviderError) Error() string {
	return "payments: " + e.Op + ": " + e.Code + ": " + e.Message
}

func (e *ProviderError) Unwrap() error { return e.Class }
