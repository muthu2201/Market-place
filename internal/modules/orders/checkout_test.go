package orders_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/modules/ledger"
	"github.com/muthu2201/market-place/internal/modules/orders"
	"github.com/muthu2201/market-place/internal/modules/payments"
	"github.com/muthu2201/market-place/internal/modules/tax"
	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/config"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/dbtest"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/money"
	"github.com/muthu2201/market-place/internal/platform/problem"
	"github.com/muthu2201/market-place/internal/testsupport/fixtures"
	"github.com/muthu2201/market-place/internal/testsupport/gatewaysim"
)

type harness struct {
	db      *db.DB
	svc     *orders.Service
	ledger  *ledger.Service
	gateway *gatewaysim.Harness
	vault   interface{ BlindIndex(string) []byte }
	clk     *clock.Fixed
	ctx     context.Context
}

func newHarness(t *testing.T, route bool) *harness {
	t.Helper()
	d := dbtest.Fresh(t)
	ctx := dbtest.Ctx(t)
	gw := gatewaysim.Start(t)

	provider, err := payments.NewRazorpay(payments.RazorpayConfig{
		BaseURL: gw.URL(), KeyID: gw.Cfg.KeyID, KeySecret: gw.Cfg.KeySecret,
		WebhookSecret: gw.Cfg.WebhookSecret, RouteMode: route,
		Timeout: 10 * time.Second, MaxRetries: 1, AllowPrivateHosts: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	led := ledger.New(dbtest.Metrics())
	policy := tax.DefaultPolicy()
	policy.PlatformGSTIN = "33AAAAA0000A1Z5"
	policy.PlatformStateCode = 33

	clk := clock.NewFixed(time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC))
	svc, err := orders.NewService(orders.Options{
		DB: d, Ledger: led, Provider: provider, TaxPolicy: policy,
		Payments:  config.PaymentsConfig{Provider: provider.Name(), SettlementHoldDays: 14},
		Platform:  config.PlatformConfig{Currency: "INR", DownloadsPerLicense: 10},
		Clock:     clk,
		Log:       slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
		Metrics:   dbtest.Metrics(),
		PSPFeeBps: 200, PSPFeeGSTBps: 1800,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{db: d, svc: svc, ledger: led, gateway: gw, clk: clk, ctx: ctx}
}

// seedRouteSeller creates a seller whose linked account exists AND is activated
// at the provider, which is what Route requires before a transfer will settle.
func (h *harness) seedRouteSeller(t *testing.T, handle string) fixtures.Seller {
	t.Helper()
	vault := fixtures.TestVault(t)
	spec := fixtures.DefaultSellerSpec(handle)

	// Create the account at the provider so the split instruction resolves.
	provider, err := payments.NewRazorpay(payments.RazorpayConfig{
		BaseURL: h.gateway.URL(), KeyID: h.gateway.Cfg.KeyID, KeySecret: h.gateway.Cfg.KeySecret,
		WebhookSecret: h.gateway.Cfg.WebhookSecret, RouteMode: true,
		Timeout: 10 * time.Second, AllowPrivateHosts: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	acct, err := provider.CreateLinkedAccount(h.ctx, payments.LinkedAccountRequest{
		SellerReference: handle, LegalName: "Seller " + handle,
		Email: handle + "@sellers.example.com", IdempotencyKey: "acct:" + handle,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.gateway.Activate(t, acct.ProviderAccountID, "activated")
	spec.ProviderAccount = acct.ProviderAccountID
	return fixtures.NewSeller(t, h.ctx, h.db, vault, spec)
}

func (h *harness) buyer(t *testing.T, email string, state int) ids.UUID {
	t.Helper()
	return fixtures.NewBuyer(t, h.ctx, h.db, fixtures.TestVault(t), email, state)
}

// payAndConfirm runs the full customer journey: start payment, play the
// customer at the gateway, then confirm with the real signature.
func (h *harness) payAndConfirm(t *testing.T, order *orders.Order, buyer ids.UUID) *orders.ConfirmResult {
	t.Helper()
	handoff, err := h.svc.BeginPayment(h.ctx, order.PublicID, buyer)
	if err != nil {
		t.Fatalf("BeginPayment: %v", err)
	}
	pay := h.gateway.Pay(t, handoff.ProviderIntentID, true)
	res, err := h.svc.ConfirmPayment(h.ctx, orders.ConfirmRequest{
		OrderPublicID:     order.PublicID,
		ProviderIntentID:  pay.OrderID,
		ProviderPaymentID: pay.PaymentID,
		Signature:         pay.Signature,
		BuyerID:           buyer,
		IP:                "203.0.113.20",
	})
	if err != nil {
		t.Fatalf("ConfirmPayment: %v", err)
	}
	return res
}

func TestFullPurchaseJourney(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "studioalpha")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{
		Title: "Vector icon pack", PriceMinor: 200000, Publish: true,
	})
	buyer := h.buyer(t, "buyer1@example.com", 33)

	order, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items:          []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
		IdempotencyKey: "checkout-1", IP: "203.0.113.20",
	})
	if err != nil {
		t.Fatalf("Checkout: %v", err)
	}

	// Same state as the seller, so CGST + SGST at 9% each on Rs 2,000.
	if order.GrandTotal.Decimal() != "2360.00" {
		t.Fatalf("grand total = %s, want 2360.00", order.GrandTotal.Decimal())
	}
	if order.TaxTotal.Decimal() != "360.00" {
		t.Fatalf("tax total = %s", order.TaxTotal.Decimal())
	}
	if order.Status != orders.StatusDraft {
		t.Fatalf("status = %s", order.Status)
	}
	if order.Number == "" {
		t.Fatal("an order must carry a human-readable number")
	}

	res := h.payAndConfirm(t, order, buyer)
	if res.AlreadyConfirmed {
		t.Fatal("first confirmation must not report a replay")
	}
	if res.Order.Status != orders.StatusFulfilled {
		t.Fatalf("status after confirmation = %s", res.Order.Status)
	}
	if len(res.Licenses) != 1 {
		t.Fatalf("expected one licence, got %d", len(res.Licenses))
	}
	if res.Licenses[0].DownloadLimit != 10 {
		t.Fatalf("download limit = %d", res.Licenses[0].DownloadLimit)
	}

	// ---- the ledger must balance and distribute exactly -------------------
	if err := h.ledger.AssertBalanced(h.ctx, h.db); err != nil {
		t.Fatal(err)
	}
	sellerPayable, err := h.ledger.SellerAccount(h.ctx, h.db, seller.ID, "payable", money.INR)
	if err != nil {
		t.Fatal(err)
	}
	payable, err := h.ledger.Balance(h.ctx, h.db, sellerPayable)
	if err != nil {
		t.Fatal(err)
	}
	if payable != 212560 { // 2360.00 - 180.00 - 32.40 - 20.00 - 2.00
		t.Fatalf("seller payable = %d, want 212560", payable)
	}
	commission, _ := h.ledger.BalanceOf(h.ctx, h.db, "platform.income.commission", money.INR)
	if commission.Decimal() != "180.00" {
		t.Fatalf("commission income = %s", commission.Decimal())
	}
	tcs, _ := h.ledger.BalanceOf(h.ctx, h.db, "platform.payable.tcs", money.INR)
	if tcs.Decimal() != "20.00" {
		t.Fatalf("TCS payable = %s", tcs.Decimal())
	}
	tds, _ := h.ledger.BalanceOf(h.ctx, h.db, "platform.payable.tds_194o", money.INR)
	if tds.Decimal() != "2.00" {
		t.Fatalf("TDS payable = %s", tds.Decimal())
	}
	gst, _ := h.ledger.BalanceOf(h.ctx, h.db, "platform.payable.gst_output", money.INR)
	if gst.Decimal() != "32.40" {
		t.Fatalf("GST on commission = %s", gst.Decimal())
	}
	// The clearing account holds what remains after the provider's fee.
	clearing, _ := h.ledger.BalanceOf(h.ctx, h.db, "platform.clearing.razorpay", money.INR)
	if clearing.Decimal() != "2304.31" { // 2360.00 - 47.20 - 8.49
		t.Fatalf("provider clearing = %s, want 2304.31", clearing.Decimal())
	}
	feeExpense, _ := h.ledger.BalanceOf(h.ctx, h.db, "platform.expense.psp_fee", money.INR)
	if feeExpense.Decimal() != "47.20" {
		t.Fatalf("processing fee expense = %s", feeExpense.Decimal())
	}

	// ---- the settlement is held, not paid ---------------------------------
	var transferStatus string
	var holdUntil time.Time
	if err := h.db.QueryRow(h.ctx,
		`SELECT status, hold_until FROM payment_transfers WHERE seller_id = $1`, seller.ID,
	).Scan(&transferStatus, &holdUntil); err != nil {
		t.Fatal(err)
	}
	if transferStatus != "on_hold" {
		t.Fatalf("transfer status = %s, want on_hold: the protection window is what contains chargeback exposure", transferStatus)
	}
	if !holdUntil.After(order.CreatedAt.Add(13 * 24 * time.Hour)) {
		t.Fatalf("hold until %s is shorter than the configured protection window", holdUntil)
	}

	// ---- turnover advanced for both thresholds ----------------------------
	var gross int64
	if err := h.db.QueryRow(h.ctx,
		`SELECT gross_supply FROM seller_turnover WHERE seller_id = $1`, seller.ID).Scan(&gross); err != nil {
		t.Fatal(err)
	}
	if gross != 200000 {
		t.Fatalf("seller turnover = %d, want 200000 (tax-exclusive value)", gross)
	}

	// ---- both invoices raised ---------------------------------------------
	var sellerInv, commissionInv int
	if err := h.db.QueryRow(h.ctx,
		`SELECT count(*) FILTER (WHERE kind='seller_supply'), count(*) FILTER (WHERE kind='platform_commission')
		   FROM invoices WHERE order_id = $1`, order.ID).Scan(&sellerInv, &commissionInv); err != nil {
		t.Fatal(err)
	}
	if sellerInv != 1 || commissionInv != 1 {
		t.Fatalf("invoices: seller=%d commission=%d; the seller's supply and the platform's commission are separate supplies", sellerInv, commissionInv)
	}

	// ---- events published for downstream consumers ------------------------
	// license.issued is keyed by the licence, the order events by the order, so
	// the topics are asserted by name rather than by a count.
	rows, err := h.db.Query(h.ctx,
		`SELECT DISTINCT topic FROM outbox_messages ORDER BY topic`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	published := map[string]bool{}
	for rows.Next() {
		var topic string
		if err := rows.Scan(&topic); err != nil {
			t.Fatal(err)
		}
		published[topic] = true
	}
	for _, want := range []string{"order.paid", "order.fulfilled", "license.issued"} {
		if !published[want] {
			t.Errorf("event %q was not published; published: %v", want, published)
		}
	}
	// Every order event must carry the ordering key, so two updates to one
	// order can never be delivered out of sequence.
	var unkeyed int
	if err := h.db.QueryRow(h.ctx,
		`SELECT count(*) FROM outbox_messages WHERE topic LIKE 'order.%' AND ordering_key IS NULL`).Scan(&unkeyed); err != nil {
		t.Fatal(err)
	}
	if unkeyed != 0 {
		t.Fatalf("%d order events were published without an ordering key", unkeyed)
	}
}

// A second confirmation of the same payment must not double-post anything.
func TestConfirmationIsIdempotent(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "studiobeta")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 100000, Publish: true})
	buyer := h.buyer(t, "buyer2@example.com", 33)

	order, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := h.svc.BeginPayment(h.ctx, order.PublicID, buyer)
	if err != nil {
		t.Fatal(err)
	}
	pay := h.gateway.Pay(t, handoff.ProviderIntentID, true)

	req := orders.ConfirmRequest{
		OrderPublicID: order.PublicID, ProviderIntentID: pay.OrderID,
		ProviderPaymentID: pay.PaymentID, Signature: pay.Signature, BuyerID: buyer,
	}
	first, err := h.svc.ConfirmPayment(h.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.svc.ConfirmPayment(h.ctx, req)
	if err != nil {
		t.Fatalf("a repeated confirmation must succeed as a replay: %v", err)
	}
	if !second.AlreadyConfirmed {
		t.Fatal("the second confirmation must be reported as a replay")
	}
	if len(first.Licenses) != len(second.Licenses) {
		t.Fatal("a replay must not issue additional licences")
	}

	var entries, licenses, paymentRows int
	if err := h.db.QueryRow(h.ctx,
		`SELECT (SELECT count(*) FROM journal_entries WHERE reference_id = $1),
		        (SELECT count(*) FROM licenses l JOIN order_items i ON i.id = l.order_item_id WHERE i.order_id = $2),
		        (SELECT count(*) FROM payments WHERE order_id = $2)`,
		order.PublicID, order.ID).Scan(&entries, &licenses, &paymentRows); err != nil {
		t.Fatal(err)
	}
	if entries != 2 {
		t.Fatalf("expected exactly the capture and fee entries, got %d", entries)
	}
	if licenses != 1 || paymentRows != 1 {
		t.Fatalf("replay duplicated rows: licences=%d payments=%d", licenses, paymentRows)
	}
	if err := h.ledger.AssertBalanced(h.ctx, h.db); err != nil {
		t.Fatal(err)
	}
}

// The single most important negative test: a forged callback must not produce
// an entitlement.
func TestForgedSignatureNeverGrantsAnEntitlement(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "studiogamma")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 500000, Publish: true})
	buyer := h.buyer(t, "attacker@example.com", 33)

	order, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := h.svc.BeginPayment(h.ctx, order.PublicID, buyer)
	if err != nil {
		t.Fatal(err)
	}

	// The attacker knows the order id and invents a payment id and signature.
	_, err = h.svc.ConfirmPayment(h.ctx, orders.ConfirmRequest{
		OrderPublicID: order.PublicID, ProviderIntentID: handoff.ProviderIntentID,
		ProviderPaymentID: "pay_FORGED", Signature: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		BuyerID: buyer,
	})
	if err == nil {
		t.Fatal("a forged signature must be refused")
	}
	p := problem.As(err)
	if p == nil || p.Type != problem.TypePaymentFailed {
		t.Fatalf("unexpected error: %v", err)
	}

	var licenses, entries int
	if err := h.db.QueryRow(h.ctx,
		`SELECT (SELECT count(*) FROM licenses), (SELECT count(*) FROM journal_entries)`).Scan(&licenses, &entries); err != nil {
		t.Fatal(err)
	}
	if licenses != 0 || entries != 0 {
		t.Fatalf("a forged confirmation wrote data: licences=%d ledger entries=%d", licenses, entries)
	}
	// The attempt is recorded as a security event.
	var audited int
	if err := h.db.QueryRow(h.ctx,
		`SELECT count(*) FROM audit_log WHERE action = 'payment.signature_rejected'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Fatalf("a rejected signature must be audited, found %d entries", audited)
	}
}

// A buyer must not be able to confirm someone else's order.
func TestBuyerCannotConfirmAnotherBuyersOrder(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "studiodelta")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 100000, Publish: true})
	victim := h.buyer(t, "victim@example.com", 33)
	attacker := h.buyer(t, "thief@example.com", 33)

	order, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: victim, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.BeginPayment(h.ctx, order.PublicID, attacker); err == nil {
		t.Fatal("another user must not be able to start payment on this order")
	}
	handoff, err := h.svc.BeginPayment(h.ctx, order.PublicID, victim)
	if err != nil {
		t.Fatal(err)
	}
	pay := h.gateway.Pay(t, handoff.ProviderIntentID, true)
	if _, err := h.svc.ConfirmPayment(h.ctx, orders.ConfirmRequest{
		OrderPublicID: order.PublicID, ProviderIntentID: pay.OrderID,
		ProviderPaymentID: pay.PaymentID, Signature: pay.Signature, BuyerID: attacker,
	}); err == nil {
		t.Fatal("another user must not be able to confirm this order")
	}
	if _, err := h.svc.LoadOrderForBuyer(h.ctx, h.db, order.PublicID, attacker); err == nil {
		t.Fatal("another user must not be able to read this order")
	}
}

func TestCheckoutIsIdempotent(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "studioeps")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 100000, Publish: true})
	buyer := h.buyer(t, "idem@example.com", 33)

	req := orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items:          []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
		IdempotencyKey: "same-key",
	}
	first, err := h.svc.Checkout(h.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.svc.Checkout(h.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if first.PublicID != second.PublicID {
		t.Fatalf("one idempotency key produced two orders: %s and %s", first.PublicID, second.PublicID)
	}

	// The same key with DIFFERENT contents must be refused, not replayed:
	// replaying would hand this caller the other request's order.
	other := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 999900, Publish: true})
	req.Items = []orders.CheckoutItem{{ProductPublicID: other.PublicID, VariantPublicID: other.VariantPublicID}}
	if _, err := h.svc.Checkout(h.ctx, req); err == nil {
		t.Fatal("reusing an idempotency key for a different request must be refused")
	}
}

// Prices come from the catalogue, never from the request. There is no field a
// client can send to change what it pays.
func TestPriceIsReadServerSide(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "studiozeta")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 750000, Publish: true})
	buyer := h.buyer(t, "price@example.com", 33)

	order, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if order.ItemsTotal.Minor() != 750000 {
		t.Fatalf("items total = %d, want the catalogue price 750000", order.ItemsTotal.Minor())
	}
	if order.GrandTotal.Decimal() != "8850.00" { // 7500 + 18%
		t.Fatalf("grand total = %s", order.GrandTotal.Decimal())
	}
}

func TestUnpublishedProductCannotBeBought(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "studioeta")
	draft := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 100000, Publish: false})
	buyer := h.buyer(t, "draft@example.com", 33)

	_, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: draft.PublicID, VariantPublicID: draft.VariantPublicID}},
	})
	if err == nil {
		t.Fatal("a draft product must not be purchasable")
	}
}

func TestInterStateOrderUsesIGST(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "studiotheta") // state 33
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 200000, Publish: true})
	buyer := h.buyer(t, "karnataka@example.com", 29)

	order, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 29,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	line := order.Lines[0].Breakdown
	if line.IGST.Decimal() != "360.00" || !line.CGST.IsZero() {
		t.Fatalf("inter-state must be IGST only: igst=%s cgst=%s", line.IGST.Decimal(), line.CGST.Decimal())
	}
}

func TestUnregisteredSellerChargesNoGST(t *testing.T) {
	h := newHarness(t, true)
	vault := fixtures.TestVault(t)
	spec := fixtures.DefaultSellerSpec("hobbyist")
	spec.GSTRegistered = false
	spec.GSTIN = ""
	spec.EntityType = "individual"
	seller := fixtures.NewSeller(t, h.ctx, h.db, vault, spec)
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 50000, Publish: true})
	buyer := h.buyer(t, "hobby@example.com", 33)

	order, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !order.TaxTotal.IsZero() {
		t.Fatalf("an unregistered seller cannot charge GST, got %s", order.TaxTotal.Decimal())
	}
	if order.GrandTotal.Decimal() != "500.00" {
		t.Fatalf("buyer should pay the list price only, got %s", order.GrandTotal.Decimal())
	}
	if !order.Lines[0].Breakdown.TCS.IsZero() {
		t.Fatal("TCS must not be collected against a seller with no GSTIN")
	}
}

func TestDomesticOrderRequiresAState(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "studioiota")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 100000, Publish: true})
	buyer := h.buyer(t, "nostate@example.com", 0)

	_, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN",
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	if err == nil {
		t.Fatal("a domestic order without a state has no determinable place of supply and must be refused")
	}
}

func TestMultiSellerOrderSplitsCorrectly(t *testing.T) {
	h := newHarness(t, true)
	s1 := h.seedRouteSeller(t, "multione")
	s2 := h.seedRouteSeller(t, "multitwo")
	p1 := fixtures.NewProduct(t, h.ctx, h.db, s1, fixtures.ProductSpec{PriceMinor: 100000, Publish: true})
	p2 := fixtures.NewProduct(t, h.ctx, h.db, s2, fixtures.ProductSpec{PriceMinor: 300000, Publish: true})
	buyer := h.buyer(t, "multi@example.com", 33)

	order, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{
			{ProductPublicID: p1.PublicID, VariantPublicID: p1.VariantPublicID},
			{ProductPublicID: p2.PublicID, VariantPublicID: p2.VariantPublicID},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if order.GrandTotal.Decimal() != "4720.00" { // (1000 + 3000) * 1.18
		t.Fatalf("grand total = %s", order.GrandTotal.Decimal())
	}

	h.payAndConfirm(t, order, buyer)
	if err := h.ledger.AssertBalanced(h.ctx, h.db); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		seller fixtures.Seller
		want   int64
	}{
		{s1, 106280}, // 1180.00 - 90.00 - 16.20 - 10.00 - 1.00
		{s2, 318840}, // 3540.00 - 270.00 - 48.60 - 30.00 - 3.00
	} {
		acct, err := h.ledger.SellerAccount(h.ctx, h.db, c.seller.ID, "payable", money.INR)
		if err != nil {
			t.Fatal(err)
		}
		bal, err := h.ledger.Balance(h.ctx, h.db, acct)
		if err != nil {
			t.Fatal(err)
		}
		if bal != c.want {
			t.Errorf("seller %s payable = %d, want %d", c.seller.Handle, bal, c.want)
		}
	}
}

func TestSellerWithoutActivatedAccountStillSellsButIsNotSettled(t *testing.T) {
	h := newHarness(t, true)
	vault := fixtures.TestVault(t)
	spec := fixtures.DefaultSellerSpec("pendingkyc")
	spec.KYCVerified = true // may list
	spec.ProviderStatus = "under_review"
	spec.ProviderAccount = "acc_not_ready"
	seller := fixtures.NewSeller(t, h.ctx, h.db, vault, spec)
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 100000, Publish: true})
	buyer := h.buyer(t, "pending@example.com", 33)

	order, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	if err != nil {
		t.Fatalf("a buyer must not be turned away because a seller's payout setup is pending: %v", err)
	}
	h.payAndConfirm(t, order, buyer)

	// The money is owed and recorded, but not routed anywhere.
	var status, account string
	if err := h.db.QueryRow(h.ctx,
		`SELECT status, provider_account_id FROM payment_transfers WHERE seller_id = $1`, seller.ID,
	).Scan(&status, &account); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || account != "pending_activation" {
		t.Fatalf("transfer = %s / %s; an unready seller's share must not be routed", status, account)
	}
	acct, _ := h.ledger.SellerAccount(h.ctx, h.db, seller.ID, "payable", money.INR)
	bal, _ := h.ledger.Balance(h.ctx, h.db, acct)
	if bal != 106280 {
		t.Fatalf("the seller is still owed their share: payable = %d", bal)
	}
	if err := h.ledger.AssertBalanced(h.ctx, h.db); err != nil {
		t.Fatal(err)
	}
}

func TestLimitedEditionCannotOversell(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "limitedrun")
	one := 1
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{
		PriceMinor: 100000, Publish: true, MaxSales: &one,
	})
	b1 := h.buyer(t, "first@example.com", 33)
	b2 := h.buyer(t, "second@example.com", 33)

	o1, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: b1, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.payAndConfirm(t, o1, b1)

	if _, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: b2, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	}); err == nil {
		t.Fatal("a sold-out limited edition must not be purchasable again")
	}
}

func TestDuplicateLineIsRefused(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "studiokappa")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 100000, Publish: true})
	buyer := h.buyer(t, "dupe@example.com", 33)

	_, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{
			{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID},
			{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID},
		},
	})
	if err == nil {
		t.Fatal("a digital licence is issued once per order; a duplicate line must be refused")
	}
}
