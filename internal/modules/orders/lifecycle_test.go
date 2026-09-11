package orders_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/modules/orders"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/platform/money"
	"github.com/muthu2201/market-place/internal/testsupport/fixtures"
	"github.com/muthu2201/market-place/internal/testsupport/gatewaysim"
)

// A refund must return the buyer's money, reverse every component
// proportionally, keep the ledger balanced, and leave the processing fee as a
// platform cost because the network does not return it.
func TestFullRefundReversesEveryComponent(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "refundseller")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 200000, Publish: true})
	buyer := h.buyer(t, "refundbuyer@example.com", 33)

	order, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.payAndConfirm(t, order, buyer)

	out, err := h.svc.Refund(h.ctx, orders.RefundRequest{
		OrderPublicID: order.PublicID, Reason: "buyer_request", RequestedBy: buyer,
	})
	if err != nil {
		t.Fatalf("Refund: %v", err)
	}
	if out.Amount.Decimal() != "2360.00" {
		t.Fatalf("refund amount = %s", out.Amount.Decimal())
	}
	if out.OrderStatus != orders.StatusRefunded {
		t.Fatalf("order status = %s", out.OrderStatus)
	}
	if out.SellerRecovery != "transfer_reversal" {
		t.Fatalf("recovery = %s; the settlement had not left yet", out.SellerRecovery)
	}
	if !out.ProcessingFeeRetained.IsPositive() {
		t.Fatal("the processing fee is not returned on a refund and must be recorded as a platform cost")
	}
	if out.ProcessingFeeRetained.Decimal() != "47.20" {
		t.Fatalf("retained fee = %s, want 47.20", out.ProcessingFeeRetained.Decimal())
	}

	if err := h.ledger.AssertBalanced(h.ctx, h.db); err != nil {
		t.Fatal(err)
	}
	// Every component nets to zero after a full refund.
	for _, c := range []struct{ code, want string }{
		{"platform.income.commission", "0.00"},
		{"platform.payable.gst_output", "0.00"},
		{"platform.payable.tcs", "0.00"},
		{"platform.payable.tds_194o", "0.00"},
	} {
		bal, err := h.ledger.BalanceOf(h.ctx, h.db, c.code, money.INR)
		if err != nil {
			t.Fatal(err)
		}
		if bal.Decimal() != c.want {
			t.Errorf("%s = %s after a full refund, want %s", c.code, bal.Decimal(), c.want)
		}
	}
	acct, _ := h.ledger.SellerAccount(h.ctx, h.db, seller.ID, "payable", money.INR)
	bal, _ := h.ledger.Balance(h.ctx, h.db, acct)
	if bal != 0 {
		t.Fatalf("seller payable = %d after a full refund, want 0", bal)
	}
	// The processing cost stays with the platform: that is the real cost of a refund.
	feeExpense, _ := h.ledger.BalanceOf(h.ctx, h.db, "platform.expense.psp_fee", money.INR)
	if feeExpense.Decimal() != "47.20" {
		t.Fatalf("processing fee expense = %s; it must not be reversed", feeExpense.Decimal())
	}

	// The entitlement is withdrawn.
	var licenseStatus string
	if err := h.db.QueryRow(h.ctx, `
		SELECT l.status FROM licenses l JOIN order_items i ON i.id = l.order_item_id
		 WHERE i.order_id = $1`, order.ID).Scan(&licenseStatus); err != nil {
		t.Fatal(err)
	}
	if licenseStatus != "refunded" {
		t.Fatalf("licence status = %s after refund", licenseStatus)
	}
}

func TestPartialRefundScalesEveryComponent(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "partialseller")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 200000, Publish: true})
	buyer := h.buyer(t, "partial@example.com", 33)

	order, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.payAndConfirm(t, order, buyer)

	half := money.MustNew(118000, money.INR) // half of 2360.00
	out, err := h.svc.Refund(h.ctx, orders.RefundRequest{
		OrderPublicID: order.PublicID, Amount: &half,
		Reason: "buyer_request", RequestedBy: buyer,
	})
	if err != nil {
		t.Fatalf("partial refund: %v", err)
	}
	if out.OrderStatus != orders.StatusPartiallyRefunded {
		t.Fatalf("status = %s", out.OrderStatus)
	}
	if err := h.ledger.AssertBalanced(h.ctx, h.db); err != nil {
		t.Fatal(err)
	}
	commission, _ := h.ledger.BalanceOf(h.ctx, h.db, "platform.income.commission", money.INR)
	if commission.Decimal() != "90.00" {
		t.Fatalf("half the commission should remain: %s", commission.Decimal())
	}
	// Refunding more than the remainder must be refused.
	tooMuch := money.MustNew(200000, money.INR)
	if _, err := h.svc.Refund(h.ctx, orders.RefundRequest{
		OrderPublicID: order.PublicID, Amount: &tooMuch,
		Reason: "buyer_request", RequestedBy: buyer,
	}); err == nil {
		t.Fatal("over-refunding must be refused")
	}
}

// The declared refund policy is what makes "no refund once downloaded" fair and
// enforceable: it was disclosed at purchase and the download is evidenced.
func TestRefundPolicyIsEnforcedAfterDownload(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "policyseller")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 100000, Publish: true})
	buyer := h.buyer(t, "policy@example.com", 33)

	order, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	res := h.payAndConfirm(t, order, buyer)

	// Record a served download, which is the evidence the policy turns on.
	var licenseID ids.UUID
	if err := h.db.QueryRow(h.ctx,
		`SELECT id FROM licenses WHERE public_id = $1`, res.Licenses[0].PublicID).Scan(&licenseID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(h.ctx, `
		INSERT INTO download_events (license_id, asset_id, user_id, bytes_sent, outcome)
		VALUES ($1,$2,$3,1048576,'served')`, licenseID, product.AssetID, buyer); err != nil {
		t.Fatal(err)
	}

	_, err = h.svc.Refund(h.ctx, orders.RefundRequest{
		OrderPublicID: order.PublicID, Reason: "buyer_request", RequestedBy: buyer,
	})
	if err == nil {
		t.Fatal("a downloaded item under a no-refund-after-download policy must be refused")
	}

	// Staff can override, and the override is audited.
	if _, err := h.svc.Refund(h.ctx, orders.RefundRequest{
		OrderPublicID: order.PublicID, Reason: "goodwill",
		RequestedBy: buyer, ActorIsStaff: true,
	}); err != nil {
		t.Fatalf("a staff override must be possible: %v", err)
	}
	var overrides int
	if err := h.db.QueryRow(h.ctx,
		`SELECT count(*) FROM audit_log WHERE action = 'order.refunded' AND metadata->>'staff_override' = 'true'`,
	).Scan(&overrides); err != nil {
		t.Fatal(err)
	}
	if overrides != 1 {
		t.Fatalf("a staff override must be audited, found %d", overrides)
	}
}

// The settlement hold is the wallet-free answer to chargeback exposure: before
// the window closes nothing has moved, so there is nothing to claw back.
func TestSettlementReleasesOnlyAfterTheProtectionWindow(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "settleseller")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 200000, Publish: true})
	buyer := h.buyer(t, "settle@example.com", 33)

	order, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.payAndConfirm(t, order, buyer)

	// Still inside the window: nothing is released.
	res, err := h.svc.ReleaseDueSettlements(h.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.Released != 0 {
		t.Fatalf("released %d settlements inside the protection window", res.Released)
	}

	// Move the hold into the past, as the passage of time would.
	if _, err := h.db.Exec(h.ctx,
		`UPDATE payment_transfers SET hold_until = now() - INTERVAL '1 day'`); err != nil {
		t.Fatal(err)
	}
	res, err = h.svc.ReleaseDueSettlements(h.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.Released != 1 {
		t.Fatalf("released %d of 1 (held: %v)", res.Released, res.HeldReasons)
	}
	if err := h.ledger.AssertBalanced(h.ctx, h.db); err != nil {
		t.Fatal(err)
	}

	// 5% rolling reserve withheld from 2125.60 -> 106.28, leaving 2019.32.
	reserveAcct, _ := h.ledger.SellerAccount(h.ctx, h.db, seller.ID, "reserve", money.INR)
	reserve, _ := h.ledger.Balance(h.ctx, h.db, reserveAcct)
	if reserve != 10628 {
		t.Fatalf("rolling reserve = %d, want 10628", reserve)
	}
	payableAcct, _ := h.ledger.SellerAccount(h.ctx, h.db, seller.ID, "payable", money.INR)
	payable, _ := h.ledger.Balance(h.ctx, h.db, payableAcct)
	if payable != 0 {
		t.Fatalf("seller payable = %d after release, want 0", payable)
	}

	// A second pass must not release the same transfer twice.
	res, err = h.svc.ReleaseDueSettlements(h.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.Released != 0 {
		t.Fatal("a released settlement must not be released again")
	}
}

func TestSettlementIsHeldWhileADisputeIsOpen(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "disputeseller")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 100000, Publish: true})
	buyer := h.buyer(t, "dispute@example.com", 33)

	order, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.payAndConfirm(t, order, buyer)

	var itemID ids.UUID
	if err := h.db.QueryRow(h.ctx, `SELECT id FROM order_items WHERE order_id = $1`, order.ID).Scan(&itemID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(h.ctx, `
		INSERT INTO disputes (id, public_id, order_item_id, opened_by, category, description, status)
		VALUES ($1,$2,$3,$4,'not_as_described','The files do not match the preview shown on the listing.','open')`,
		ids.NewUUIDv7(), ids.NewPublic(ids.PrefixDispute), itemID, buyer); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(h.ctx, `UPDATE payment_transfers SET hold_until = now() - INTERVAL '1 day'`); err != nil {
		t.Fatal(err)
	}

	res, err := h.svc.ReleaseDueSettlements(h.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.Released != 0 || res.Held != 1 {
		t.Fatalf("an open dispute must hold settlement: released=%d held=%d", res.Released, res.Held)
	}
	if len(res.HeldReasons) == 0 {
		t.Fatal("a hold must carry a reason an operator can quote to the seller")
	}
}

// A post-settlement refund must be recovered from the next settlement, never by
// creating an internal debit balance.
func TestPostSettlementRefundCreatesAnOffsetNotADebtBalance(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "offsetseller")
	first := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 200000, Publish: true})
	second := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 500000, Publish: true})
	buyer := h.buyer(t, "offset@example.com", 33)

	o1, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: first.PublicID, VariantPublicID: first.VariantPublicID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.payAndConfirm(t, o1, buyer)

	// Settle it away.
	if _, err := h.db.Exec(h.ctx, `UPDATE payment_transfers SET hold_until = now() - INTERVAL '1 day'`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.ReleaseDueSettlements(h.ctx, 100); err != nil {
		t.Fatal(err)
	}

	// Now refund it.
	out, err := h.svc.Refund(h.ctx, orders.RefundRequest{
		OrderPublicID: o1.PublicID, Reason: "fraud", RequestedBy: buyer, ActorIsStaff: true,
	})
	if err != nil {
		t.Fatalf("Refund: %v", err)
	}
	if out.SellerRecovery != "future_settlement_offset" {
		t.Fatalf("recovery = %s; the settlement had already left", out.SellerRecovery)
	}
	if err := h.ledger.AssertBalanced(h.ctx, h.db); err != nil {
		t.Fatal(err)
	}

	// The seller's payable must NOT be negative: no internal debt balance.
	payableAcct, _ := h.ledger.SellerAccount(h.ctx, h.db, seller.ID, "payable", money.INR)
	payable, _ := h.ledger.Balance(h.ctx, h.db, payableAcct)
	if payable < 0 {
		t.Fatalf("seller payable = %d; the platform must never run an internal debit balance", payable)
	}
	var offsetAmount, offsetApplied int64
	var offsetStatus string
	if err := h.db.QueryRow(h.ctx,
		`SELECT amount_minor, applied_minor, status FROM settlement_offsets WHERE seller_id = $1`,
		seller.ID).Scan(&offsetAmount, &offsetApplied, &offsetStatus); err != nil {
		t.Fatal(err)
	}
	if offsetAmount != 212560 || offsetStatus != "outstanding" {
		t.Fatalf("offset = %d (%s), want 212560 outstanding", offsetAmount, offsetStatus)
	}

	// The next sale's settlement nets the offset out.
	o2, err := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: second.PublicID, VariantPublicID: second.VariantPublicID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.payAndConfirm(t, o2, buyer)
	if _, err := h.db.Exec(h.ctx,
		`UPDATE payment_transfers SET hold_until = now() - INTERVAL '1 day' WHERE status IN ('on_hold','pending')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.ReleaseDueSettlements(h.ctx, 100); err != nil {
		t.Fatal(err)
	}

	if err := h.db.QueryRow(h.ctx,
		`SELECT applied_minor, status FROM settlement_offsets WHERE seller_id = $1`,
		seller.ID).Scan(&offsetApplied, &offsetStatus); err != nil {
		t.Fatal(err)
	}
	if offsetStatus != "settled" || offsetApplied != 212560 {
		t.Fatalf("the offset should have been recovered: applied=%d status=%s", offsetApplied, offsetStatus)
	}
	if err := h.ledger.AssertBalanced(h.ctx, h.db); err != nil {
		t.Fatal(err)
	}
	offsetBal, _ := h.ledger.BalanceOf(h.ctx, h.db, "platform.receivable.seller_offset", money.INR)
	if !offsetBal.IsZero() {
		t.Fatalf("recoverable balance = %s after recovery, want zero", offsetBal.Decimal())
	}
}

// ---- webhooks ---------------------------------------------------------------

func TestWebhookConfirmsPaymentWhenTheBuyerClosesTheTab(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "webhookseller")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 200000, Publish: true})
	buyer := h.buyer(t, "webhook@example.com", 33)

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
	// The customer pays, but the browser never posts back.
	pay := h.gateway.Pay(t, handoff.ProviderIntentID, true)

	body := webhookBody(t, "payment.captured", map[string]any{
		"id": pay.PaymentID, "order_id": pay.OrderID, "status": "captured",
		"amount": float64(236000), "currency": "INR",
	})
	out, err := h.svc.HandleWebhook(h.ctx, signedHeader(t, h, body), body)
	if err != nil {
		t.Fatalf("HandleWebhook: %v", err)
	}
	if !out.Processed {
		t.Fatalf("webhook outcome: %+v", out)
	}

	reloaded, err := h.svc.LoadOrder(h.ctx, h.db, order.PublicID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Status != orders.StatusFulfilled {
		t.Fatalf("the webhook must complete the order even without a callback, got %s", reloaded.Status)
	}
	if err := h.ledger.AssertBalanced(h.ctx, h.db); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookIsDeduplicatedAndTamperedReplayIsDetected(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "dedupeseller")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 100000, Publish: true})
	buyer := h.buyer(t, "dedupe@example.com", 33)

	order, _ := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	handoff, _ := h.svc.BeginPayment(h.ctx, order.PublicID, buyer)
	pay := h.gateway.Pay(t, handoff.ProviderIntentID, true)

	body := webhookBody(t, "payment.captured", map[string]any{
		"id": pay.PaymentID, "order_id": pay.OrderID, "status": "captured",
		"amount": float64(118000), "currency": "INR",
	})
	hdr := signedHeader(t, h, body)
	hdr.Set("X-Razorpay-Event-Id", "evt_dedupe")

	first, err := h.svc.HandleWebhook(h.ctx, hdr, body)
	if err != nil {
		t.Fatal(err)
	}
	if first.Duplicate {
		t.Fatal("the first delivery is not a duplicate")
	}
	second, err := h.svc.HandleWebhook(h.ctx, hdr, body)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Duplicate || second.ReplayMismatch {
		t.Fatalf("an identical retry is an ordinary duplicate: %+v", second)
	}

	// Same event id, different content: that is a replay attempt, not a retry.
	tampered := webhookBody(t, "payment.captured", map[string]any{
		"id": pay.PaymentID, "order_id": pay.OrderID, "status": "captured",
		"amount": float64(999999), "currency": "INR",
	})
	hdr2 := signedHeader(t, h, tampered)
	hdr2.Set("X-Razorpay-Event-Id", "evt_dedupe")
	third, err := h.svc.HandleWebhook(h.ctx, hdr2, tampered)
	if err != nil {
		t.Fatal(err)
	}
	if !third.ReplayMismatch {
		t.Fatal("a reused event id carrying different content must be flagged as a replay")
	}
	var flagged int
	if err := h.db.QueryRow(h.ctx,
		`SELECT count(*) FROM audit_log WHERE action = 'webhook.replay_mismatch'`).Scan(&flagged); err != nil {
		t.Fatal(err)
	}
	if flagged != 1 {
		t.Fatalf("a replay mismatch must be audited, found %d", flagged)
	}
}

func TestForgedWebhookIsRefusedAndRecordsNothing(t *testing.T) {
	h := newHarness(t, true)
	body := webhookBody(t, "payment.captured", map[string]any{
		"id": "pay_EVIL", "order_id": "order_EVIL", "status": "captured",
		"amount": float64(999999999), "currency": "INR",
	})
	hdr := http.Header{}
	hdr.Set("X-Razorpay-Signature", "deadbeef"+"00112233445566778899aabbccddeeff00112233445566778899aabbccdd")

	if _, err := h.svc.HandleWebhook(h.ctx, hdr, body); err == nil {
		t.Fatal("a forged webhook must be refused")
	}
	var recorded, journal int
	if err := h.db.QueryRow(h.ctx,
		`SELECT (SELECT count(*) FROM provider_webhook_events), (SELECT count(*) FROM journal_entries)`,
	).Scan(&recorded, &journal); err != nil {
		t.Fatal(err)
	}
	if recorded != 0 || journal != 0 {
		t.Fatalf("a forged webhook wrote data: webhook rows=%d ledger entries=%d", recorded, journal)
	}
	var audited int
	if err := h.db.QueryRow(h.ctx,
		`SELECT count(*) FROM audit_log WHERE action = 'webhook.signature_rejected'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Fatalf("a rejected webhook signature must be audited, found %d", audited)
	}
}

func TestChargebackFreezesSettlementAndBooksTheLoss(t *testing.T) {
	h := newHarness(t, true)
	seller := h.seedRouteSeller(t, "cbseller")
	product := fixtures.NewProduct(t, h.ctx, h.db, seller, fixtures.ProductSpec{PriceMinor: 200000, Publish: true})
	buyer := h.buyer(t, "cb@example.com", 33)

	order, _ := h.svc.Checkout(h.ctx, orders.CheckoutRequest{
		BuyerID: buyer, BuyerCountry: "IN", BuyerStateCode: 33,
		Items: []orders.CheckoutItem{{ProductPublicID: product.PublicID, VariantPublicID: product.VariantPublicID}},
	})
	handoff, _ := h.svc.BeginPayment(h.ctx, order.PublicID, buyer)
	pay := h.gateway.Pay(t, handoff.ProviderIntentID, true)
	if _, err := h.svc.ConfirmPayment(h.ctx, orders.ConfirmRequest{
		OrderPublicID: order.PublicID, ProviderIntentID: pay.OrderID,
		ProviderPaymentID: pay.PaymentID, Signature: pay.Signature, BuyerID: buyer,
	}); err != nil {
		t.Fatal(err)
	}

	// A chargeback lands.
	body := webhookBody(t, "payment.dispute.created", map[string]any{
		"id": "disp_1", "payment_id": pay.PaymentID, "amount": float64(236000),
		"currency": "INR", "network": "RuPay", "reason_code": "13.1",
	})
	hdr := signedHeader(t, h, body)
	hdr.Set("X-Razorpay-Event-Id", "evt_disp_1")
	if _, err := h.svc.HandleWebhook(h.ctx, hdr, body); err != nil {
		t.Fatalf("dispute webhook: %v", err)
	}

	reloaded, _ := h.svc.LoadOrder(h.ctx, h.db, order.PublicID)
	if reloaded.Status != orders.StatusDisputed {
		t.Fatalf("status = %s after a chargeback", reloaded.Status)
	}
	var network, cbStatus string
	var respondBy time.Time
	if err := h.db.QueryRow(h.ctx,
		`SELECT network, status, respond_by FROM chargebacks WHERE order_id = $1`, order.ID,
	).Scan(&network, &cbStatus, &respondBy); err != nil {
		t.Fatal(err)
	}
	if network != "rupay" {
		t.Fatalf("network = %s", network)
	}
	// RuPay's representment window is the tightest of the networks.
	if d := respondBy.Sub(h.clk.Now()); d > 8*24*time.Hour || d < 6*24*time.Hour {
		t.Fatalf("RuPay representment deadline is %v away; it must reflect the network's tighter window", d)
	}

	// Settlement must be frozen even though the original hold may have elapsed.
	if _, err := h.db.Exec(h.ctx, `UPDATE payment_transfers SET hold_until = now() - INTERVAL '1 day'`); err != nil {
		t.Fatal(err)
	}
	res, err := h.svc.ReleaseDueSettlements(h.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.Released != 0 {
		t.Fatal("a disputed order must not settle")
	}

	// The representment fails.
	lost := webhookBody(t, "payment.dispute.lost", map[string]any{
		"id": "disp_1", "payment_id": pay.PaymentID, "amount": float64(236000),
		"currency": "INR", "network": "RuPay",
	})
	hdr2 := signedHeader(t, h, lost)
	hdr2.Set("X-Razorpay-Event-Id", "evt_disp_lost")
	if _, err := h.svc.HandleWebhook(h.ctx, hdr2, lost); err != nil {
		t.Fatalf("dispute lost webhook: %v", err)
	}

	final, _ := h.svc.LoadOrder(h.ctx, h.db, order.PublicID)
	if final.Status != orders.StatusChargebackLost {
		t.Fatalf("status = %s", final.Status)
	}
	if err := h.ledger.AssertBalanced(h.ctx, h.db); err != nil {
		t.Fatal(err)
	}
	// The seller's share was not settled, so it is simply reversed; the
	// platform absorbs its own share of the charged-back amount.
	payableAcct, _ := h.ledger.SellerAccount(h.ctx, h.db, seller.ID, "payable", money.INR)
	payable, _ := h.ledger.Balance(h.ctx, h.db, payableAcct)
	if payable != 0 {
		t.Fatalf("seller payable = %d after a lost chargeback, want 0", payable)
	}
	loss, _ := h.ledger.BalanceOf(h.ctx, h.db, "platform.expense.chargeback_loss", money.INR)
	if !loss.IsPositive() {
		t.Fatal("the platform's share of a lost chargeback must be booked as a loss, not silently vanish")
	}
}

// ---- helpers ----------------------------------------------------------------

func webhookBody(t *testing.T, event string, entity map[string]any) []byte {
	t.Helper()
	kind := "payment"
	switch event {
	case "payment.dispute.created", "payment.dispute.lost", "payment.dispute.won":
		kind = "dispute"
	case "refund.processed":
		kind = "refund"
	case "transfer.processed", "transfer.failed":
		kind = "transfer"
	case "account.activated", "account.suspended":
		kind = "account"
	}
	return marshalWebhook(t, event, gatewaysim.WebhookBody(kind, entity))
}
