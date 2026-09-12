// Package orders owns the purchase lifecycle: checkout, payment confirmation,
// entitlement issue, refunds, chargebacks and settlement release.
//
// This is where the tax engine, the double-entry ledger and the payment port
// meet, so it is where the system's central invariant is maintained: every
// paise a buyer pays is recorded in balanced debits and credits, distributed to
// exactly one destination, and never held by the platform.
package orders

import (
	"time"

	"github.com/muthu2201/market-place/internal/modules/tax"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/money"
)

// Status values mirror the orders.status CHECK constraint and the
// order_transitions_allowed table, which is the authoritative state machine.
type Status string

const (
	StatusDraft             Status = "draft"
	StatusAwaitingPayment   Status = "awaiting_payment"
	StatusPaymentFailed     Status = "payment_failed"
	StatusPaid              Status = "paid"
	StatusFulfilled         Status = "fulfilled"
	StatusCompleted         Status = "completed"
	StatusCancelled         Status = "cancelled"
	StatusExpired           Status = "expired"
	StatusRefundPending     Status = "refund_pending"
	StatusPartiallyRefunded Status = "partially_refunded"
	StatusRefunded          Status = "refunded"
	StatusDisputed          Status = "disputed"
	StatusChargebackLost    Status = "chargeback_lost"
)

// CheckoutItem is one requested purchase.
type CheckoutItem struct {
	// ProductPublicID and VariantPublicID are the only identifiers a client
	// supplies. Prices are never taken from the request: they are read from the
	// catalogue server-side, which is what makes price tampering impossible.
	ProductPublicID string
	VariantPublicID string
}

// CheckoutRequest is a validated checkout.
type CheckoutRequest struct {
	BuyerID ids.UUID
	Items   []CheckoutItem
	// BuyerStateCode fixes the place of supply for a domestic sale.
	BuyerStateCode int
	BuyerCountry   string
	BuyerGSTIN     string
	IsB2B          bool
	IP             string
	IdempotencyKey string
}

// LineBreakdown is one priced line with its full tax decomposition.
type LineBreakdown struct {
	ItemID          ids.UUID
	ItemPublicID    string
	ProductID       ids.UUID
	VariantID       ids.UUID
	SellerID        ids.UUID
	SellerPublicID  string
	Title           string
	Breakdown       tax.Breakdown
	ProviderAccount string
	// SettlementHoldUntil is the end of the protection window. The seller's
	// share is not settled before it, which is how chargeback exposure is
	// contained without ever holding a balance.
	SettlementHoldUntil time.Time
}

// Order is the in-memory view.
type Order struct {
	ID                   ids.UUID
	PublicID             string
	Number               string
	BuyerID              ids.UUID
	Status               Status
	Currency             money.Currency
	ItemsTotal           money.Money
	TaxTotal             money.Money
	GrandTotal           money.Money
	Refunded             money.Money
	Lines                []LineBreakdown
	PlaceOfSupplyCountry string
	PlaceOfSupplyState   int
	CreatedAt            time.Time
	PaidAt               *time.Time
	ExpiresAt            *time.Time
}

// PaymentHandoff is what the browser needs to complete payment. It never
// contains anything that would let a client authorise a payment by itself.
type PaymentHandoff struct {
	OrderPublicID    string
	ProviderIntentID string
	Provider         string
	Amount           money.Money
	CheckoutParams   map[string]string
	ExpiresAt        time.Time
}

// ConfirmRequest carries the browser's payment callback.
type ConfirmRequest struct {
	OrderPublicID     string
	ProviderIntentID  string
	ProviderPaymentID string
	Signature         string
	BuyerID           ids.UUID
	IP                string
}

// ConfirmResult reports what confirmation produced.
type ConfirmResult struct {
	Order    *Order
	Licenses []IssuedLicense
	// AlreadyConfirmed is true when this was a replay: the browser posting the
	// callback twice, or the webhook arriving first.
	AlreadyConfirmed bool
}

// IssuedLicense is an entitlement handed to the buyer.
type IssuedLicense struct {
	PublicID      string
	ProductTitle  string
	LicenseType   string
	DownloadLimit int
	ExpiresAt     *time.Time
}

// RefundRequest asks for money back.
type RefundRequest struct {
	OrderPublicID string
	// ItemPublicID refunds one line; empty refunds the whole order.
	ItemPublicID   string
	Amount         *money.Money
	Reason         string
	RequestedBy    ids.UUID
	ActorIsStaff   bool
	Note           string
	IdempotencyKey string
}
